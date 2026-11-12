"""The consent page's permission list and its binding to the granted scopes.

A consent page shows each requested scope with a human-readable description.
The description is presentation only: the user selects a *scope identifier*,
and the authorization server grants that identifier. A description is never a
key, and two scopes may legitimately have the same description.

What the page showed is bound to the submission with a signed ``scope_details``
value: the requested scope identifiers and a language-independent identity for
each description. On approval the identifiers the user selected are taken from
the signed value, not from the form's ``scope`` field or from anything the
client reported, and the description identities are recomputed. A description
that changed while the page was open (an administrator edited ``SCOPES``, or a
backend changed what it returns) no longer matches the binding, so the request
is refused instead of granting permissions described with text the user never
saw. A language switch does not change a translated description's identity, so
the same consent remains valid.

A scope whose description cannot be obtained reliably is marked unavailable
and cannot be granted: the page shows that it is withheld, and approval of it
is refused. This is the rule for sensitive permissions whose text cannot be
vouched for.
"""

from dataclasses import dataclass

from django.core import signing
from django.utils.functional import Promise

from oauth2_provider.core.scopes import UNRELIABLE_SCOPE_DESCRIPTION


#: Salt separating this signature from the other signatures the views make.
SALT = "oauth2_provider.scope_consent"


class ScopeConsentError(Exception):
    """The submitted permission list does not match what the page showed."""


@dataclass(frozen=True)
class ScopePermission:
    """One row of the consent page.

    ``description`` is the text to show. ``identity`` is the language-independent
    identity of that description, used in the signed binding; it is ``None`` for
    a description that cannot be relied on. ``available`` says whether the user
    may consent to this scope at all.
    """

    scope: str
    description: str
    identity: str | None
    available: bool


def description_identity(description: object) -> str | None:
    """Return a language-independent identity for a scope description, or ``None``.

    A lazy translation is identified by its message id (what the backend declared),
    not by the text rendered in the current language, so switching language keeps
    the same identity while editing the configured description changes it. A plain
    string is identified by the string itself. Anything that is not a non-blank
    string (including a lazy translation without a usable message id) is unreliable.
    """
    if isinstance(description, Promise):
        args = getattr(description, "_args", ())
        kwargs = getattr(description, "_kw", {}) or {}
        message = args[0] if args else kwargs.get("singular")
        if isinstance(message, str) and message.strip():
            return f"i18n:{message}"
        return None
    if isinstance(description, str) and description.strip():
        return f"text:{description}"
    return None


def describe_scopes(scopes, application=None, request=None, backend=None) -> list[ScopePermission]:
    """Describe every scope offered on the consent page.

    ``request`` is the current Django request, passed through to the backend. A
    backend error, or a description that is not a usable string, leaves that
    scope unexplained, so it is reported unavailable and must not be granted.
    """
    if backend is None:
        from oauth2_provider.core.scopes import get_scopes_backend

        backend = get_scopes_backend()

    permissions = []
    seen = set()
    for scope in scopes:
        if scope in seen:
            # A repeated scope is one permission; oauthlib may hand a request's
            # scope list through without deduplicating it.
            continue
        seen.add(scope)
        raw = None
        try:
            getter = getattr(backend, "get_scope_description", None)
            if getter is None:
                raw = backend.get_all_scopes().get(scope)
            else:
                raw = getter(scope, application=application, request=request)
            identity = description_identity(raw)
        except Exception:
            identity = None
        if identity is None:
            permissions.append(
                ScopePermission(
                    scope=scope,
                    description=str(UNRELIABLE_SCOPE_DESCRIPTION),
                    identity=None,
                    available=False,
                )
            )
            continue
        # Rendering can fail (a translation with bad formatting, say), which leaves
        # the scope just as unexplained as a missing description.
        try:
            text = str(raw)
        except Exception:
            permissions.append(
                ScopePermission(
                    scope=scope,
                    description=str(UNRELIABLE_SCOPE_DESCRIPTION),
                    identity=None,
                    available=False,
                )
            )
            continue
        permissions.append(ScopePermission(scope=scope, description=text, identity=identity, available=True))
    return permissions


def sign_scope_details(scopes, permissions, binding) -> str:
    """Sign the permission list a consent page shows.

    ``binding`` ties the signed value to the authorization request (client,
    redirect URI, response type, state, nonce, code challenge), so a value
    signed for one request cannot be replayed into another.
    """
    return signing.dumps(
        {
            "scopes": list(scopes),
            "descriptions": {permission.scope: permission.identity for permission in permissions},
            "bound": binding,
        },
        salt=SALT,
    )


def verify_scope_details(value: str, binding) -> dict:
    """Return the signed permission list, or raise :class:`ScopeConsentError`.

    The value must carry a valid signature, be bound to the same authorization
    request, and describe exactly the scopes it lists.
    """
    try:
        payload = signing.loads(value, salt=SALT)
    except signing.BadSignature:
        raise ScopeConsentError("The permission list was not signed by this server.")
    except (TypeError, ValueError):
        raise ScopeConsentError("The permission list is malformed.")
    if not isinstance(payload, dict):
        raise ScopeConsentError("The permission list is malformed.")
    scopes = payload.get("scopes")
    descriptions = payload.get("descriptions")
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise ScopeConsentError("The permission list is malformed.")
    if not isinstance(descriptions, dict) or set(descriptions) != set(scopes):
        raise ScopeConsentError("The permission list is malformed.")
    if not all(descriptions[scope] is None or isinstance(descriptions[scope], str) for scope in scopes):
        raise ScopeConsentError("The permission list is malformed.")
    if payload.get("bound") != binding:
        raise ScopeConsentError("The permission list is for another authorization request.")
    return payload
