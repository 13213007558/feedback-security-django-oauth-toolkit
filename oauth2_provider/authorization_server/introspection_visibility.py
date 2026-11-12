"""Caller-specific visibility policy for the token introspection endpoint.

RFC 7662 section 2.2 allows the authorization server to answer an
introspection request differently for different protected resources, for
instance limiting which scopes it reports "to prevent a protected resource from
learning more about the larger network than is necessary for its operation".
A deployment where several resource servers share one introspection endpoint
can use that to keep one resource server from learning about tokens that
belong to another.

The policy decides only *what* an already-authorized caller may learn. It never
decides whether the caller may introspect at all: the endpoint authenticates
the caller and checks ``Application.can_introspect`` exactly as before, and
consults the policy only afterwards, for an active token. A policy therefore
cannot widen access, and an error in it cannot make anything visible.

A policy is a callable, or an object implementing one or more of these methods:

``get_visibility(context)``
    Return an :class:`IntrospectionVisibility`. This is the most direct form and
    expresses both decisions at once.
``can_see_active(context)``
    Return whether the caller may learn whether the token is active. When the
    method is absent, or when a bare callable is used, the default is ``True``.
``get_visible_fields(context)``
    Return an iterable of response-member names the caller may read. This is
    the simple form; combine it with ``can_see_active`` when the two decisions
    differ.

A plain callable receives an :class:`IntrospectionContext` and returns an
:class:`IntrospectionVisibility`, an iterable of field names, a mapping of field
names to truthy flags (an optional ``"active"`` key controls that member), a
``(allow_active, fields)`` pair, or any object with ``allow_active``/``fields``.

The default setting, :class:`AllFieldsPolicy`, keeps the pre-policy response: every
authorized caller reads every member the endpoint can derive. A deployment whose
resource servers share the endpoint should select a narrower policy.
:class:`IntrospectionVisibilityPolicy` is the ready-made safe default for that case:
it still lets every authorized caller learn ``active`` -- it needs that to decide
whether to use a token -- but discloses optional members only to the application the
token was issued to, so a second resource server cannot learn whose token it
queried, what it may do, or where it was meant to go. :class:`CallerResourcePolicy`
maps callers to resource identifiers, for resource servers that authenticate as
themselves and each represent a distinct audience.

Returned field names are the response members of RFC 7662 section 2.2 this
endpoint can emit: ``scope``, ``client_id``, ``username``, ``exp`` and ``aud``.
Unknown names are ignored, and ``"active"`` is not a field: it is decided by
``can_see_active``. ``username`` and ``client_id`` are tied to the token's user
and application, so a policy cannot invent a value the token does not carry.
When ``can_see_active`` is false the endpoint answers ``{"active": false}`` and
nothing else, so the token looks unknown to that caller. An inactive token is
always answered that way, whatever the policy says: RFC 7662 section 2.2
requires such a response to carry no additional information.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from oauth2_provider.models import AbstractAccessToken, AbstractApplication
from oauth2_provider.settings import oauth2_settings


#: Response members a policy may make visible, besides ``active``.
#:
#: These are the members this endpoint can derive from the stored token (RFC 7662
#: section 2.2). ``exp`` is emitted as an integer Unix timestamp and ``aud`` as the
#: RFC 8707 resource list. A deployment's own extension members are not offered:
#: they are outside the protocol's response registry, so this library cannot know
#: their sensitivity.
VISIBLE_FIELDS = frozenset({"scope", "client_id", "username", "exp", "aud"})


@dataclass(frozen=True)
class IntrospectionVisibility:
    """What one caller may learn about one active token.

    :param allow_active: whether the caller may learn that the token is active.
        When ``False`` the endpoint answers ``{"active": false}`` with no other
        member, so the token looks unknown to that caller.
    :param fields: the optional response members to disclose. Only names in
        :data:`VISIBLE_FIELDS` take effect; a field is emitted only when the token
        actually carries the corresponding value.
    """

    allow_active: bool = True
    fields: frozenset[str] = field(default_factory=frozenset)


#: Nothing at all: the token looks unknown to the caller (RFC 7662 section 2.2).
HIDDEN = IntrospectionVisibility(allow_active=False)

#: The token is known to be active, but none of its details are.
ACTIVE_ONLY = IntrospectionVisibility()

#: Every optional member this endpoint knows.
EVERYTHING = IntrospectionVisibility(allow_active=True, fields=VISIBLE_FIELDS)


@dataclass(frozen=True)
class IntrospectionContext:
    """The facts a visibility policy decides from.

    The context carries the *authenticated* caller as the endpoint found it, the
    access token it presented (if it authenticated with one), and the token being
    queried -- never a request parameter: a caller cannot name itself in the body
    or query string and change what it sees.

    :param caller: the application that authenticated for this request, either as
        itself or as the application its bearer access token was issued to.
        Always an instance of the (swappable) Application model.
    :param token: the active access token the caller asked about.
    """

    caller: AbstractApplication
    token: AbstractAccessToken

    @property
    def caller_client_id(self) -> str:
        """The authenticated caller's ``client_id``."""
        return self.caller.client_id

    @property
    def token_client_id(self) -> str | None:
        """The ``client_id`` of the token's application, or ``None``."""
        return self.token.application.client_id if self.token.application else None

    @property
    def username(self) -> str | None:
        """The token user's username, or ``None``."""
        return self.token.user.get_username() if self.token.user else None

    @property
    def audiences(self) -> list[str]:
        """The queried token's RFC 8707 resource indicators (``aud``)."""
        return list(self.token.resource or ())

    @property
    def caller_is_token_application(self) -> bool:
        """Whether the caller is the application the token was issued to."""
        return self.token.application is not None and self.token.application.pk == self.caller.pk

    @property
    def token_is_unrestricted(self) -> bool:
        """Whether the queried token has no RFC 8707 resource indicators."""
        return not self.token.resource

    def token_is_audience(self, uri: str | None = None) -> bool:
        """Whether *uri* (default: this deployment's protected-resource identifier)
        is one of the queried token's audiences, using the configured RFC 8707 matcher.

        A token without resource indicators is unrestricted: it applies to every
        resource server, and this returns ``True``. Without *uri* and without
        ``OAUTH2_PROTECTED_RESOURCE_IDENTIFIER``, this returns ``False``.
        """
        if self.token_is_unrestricted:
            return True
        if uri is None:
            uri = oauth2_settings.OAUTH2_PROTECTED_RESOURCE_IDENTIFIER
            if not uri:
                return False
        return self.token.allows_audience(uri)

    def may_read_details(self) -> bool:
        """Whether the default policy discloses optional members to this caller."""
        return self.caller_is_token_application


class IntrospectionVisibilityPolicy:
    """The restrictive policy: known active, details only to the token's application.

    The caller may always learn whether the token is active, but reads the
    optional members only if it is the application the token was issued to. A
    second resource server sharing the endpoint therefore learns a token is
    active but not whose it is, what it may do, or where it was meant to go.

    Select it with ``INTROSPECTION_VISIBILITY_POLICY`` set to
    ``"oauth2_provider.authorization_server.introspection_visibility.IntrospectionVisibilityPolicy"``
    (or the class itself). The default, :class:`AllFieldsPolicy`, instead keeps the
    pre-policy response.
    """

    @classmethod
    def get_visibility(cls, context: IntrospectionContext) -> IntrospectionVisibility:
        if context.may_read_details():
            return EVERYTHING
        return ACTIVE_ONLY


class AllFieldsPolicy:
    """The default policy: disclose every optional member to every authorized caller.

    This is the pre-policy response, kept for deployments that have not opted into a
    narrower view::

        OAUTH2_PROVIDER = {
            "INTROSPECTION_VISIBILITY_POLICY": (
                "oauth2_provider.authorization_server.introspection_visibility.AllFieldsPolicy"
            ),
        }
    """

    @staticmethod
    def get_visibility(context: IntrospectionContext) -> IntrospectionVisibility:
        return EVERYTHING


class CallerResourcePolicy:
    """An audience policy for resource servers that share an introspection endpoint.

    The default policy discloses details only to the token's own application. When
    several resource servers authenticate as themselves, a deployment can instead
    map each caller ``client_id`` to the resource identifiers it speaks for, so a
    caller also reads tokens bound to its own audience::

        from oauth2_provider.authorization_server.introspection_visibility import (
            CallerResourcePolicy,
        )

        OAUTH2_PROVIDER = {
            "INTROSPECTION_VISIBILITY_POLICY": CallerResourcePolicy(
                resources={
                    "service-a": ["https://a.example.com"],
                    "service-b": ["https://b.example.com"],
                },
            ),
        }

    A caller with no entry declares no audience. The queried token is matched with
    ``RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR`` against each declared resource;
    the caller also reads a token it was itself issued. ``allow_active`` is true
    for every authorized caller, so the deployment still distinguishes "can see
    active" from "can read fields"; use :attr:`deny_active` to hide even that
    from an unmapped or explicitly denied caller.

    The settings value may be an instance (as above) or a dotted path to a
    subclass that sets :attr:`resources`.
    """

    resources: dict[str, Iterable[str]] = {}
    deny_active: frozenset[str] = frozenset()

    def __init__(self, resources: dict[str, Iterable[str]] | None = None) -> None:
        self.resources = {str(key): tuple(value) for key, value in (resources or {}).items()}

    def resources_for(self, client_id: str) -> tuple[str, ...]:
        """The resource identifiers declared for *client_id*."""
        return tuple(self.resources.get(client_id, ()))

    def can_see_active(self, context: IntrospectionContext) -> bool:
        return context.caller_client_id not in self.deny_active

    def get_visible_fields(self, context: IntrospectionContext) -> frozenset[str]:
        if not self.can_see_active(context):
            return frozenset()
        if context.caller_is_token_application:
            return VISIBLE_FIELDS
        declared = self.resources_for(context.caller_client_id)
        if not declared:
            return frozenset()
        if any(context.token.allows_audience(uri) for uri in declared):
            return VISIBLE_FIELDS
        return frozenset()


def resolve_visibility_policy() -> Any:
    """Return the configured policy object, or the default.

    ``INTROSPECTION_VISIBILITY_POLICY`` is resolved through the settings'
    import-string machinery, so it may be a dotted path, a class, or an object.
    ``None`` means :class:`AllFieldsPolicy`, the pre-policy response.
    """
    policy = oauth2_settings.INTROSPECTION_VISIBILITY_POLICY
    return AllFieldsPolicy if policy is None else policy


def _as_fields(value: object) -> frozenset[str]:
    """Normalize a field collection, dropping anything this endpoint cannot emit."""
    if isinstance(value, dict):
        value = {name for name, enabled in value.items() if enabled}
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ValueError("visible fields must be an iterable of strings, not %r" % (value,))
    names = frozenset(name for name in value if isinstance(name, str))
    return names & VISIBLE_FIELDS


def _as_visibility(value: object) -> IntrospectionVisibility:
    """Normalize a policy return value to :class:`IntrospectionVisibility`.

    Besides that type, a policy may return an iterable of field names, a mapping of
    field names to truthy flags (with an optional ``"active"`` key), a
    ``(allow_active, fields)`` pair, or any object carrying ``allow_active`` and
    ``fields`` attributes -- the forms convenient in a short policy function.
    """
    if isinstance(value, IntrospectionVisibility):
        return IntrospectionVisibility(allow_active=bool(value.allow_active), fields=_as_fields(value.fields))
    if isinstance(value, dict):
        allow_active = bool(value.get("active", True))
        selected = {name for name, enabled in value.items() if name != "active" and enabled}
        return IntrospectionVisibility(allow_active=allow_active, fields=_as_fields(selected))
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bool):
        return IntrospectionVisibility(allow_active=value[0], fields=_as_fields(value[1]))
    if hasattr(value, "allow_active") or hasattr(value, "fields"):
        return IntrospectionVisibility(
            allow_active=bool(getattr(value, "allow_active", True)),
            fields=_as_fields(getattr(value, "fields", frozenset())),
        )
    # A bare set of field names keeps the simple policy form working; the caller
    # may still learn active.
    return IntrospectionVisibility(allow_active=True, fields=_as_fields(value))


def evaluate_visibility(
    policy: Any, context: IntrospectionContext
) -> tuple[IntrospectionVisibility, Exception | None]:
    """Ask *policy* what *context*'s caller may learn, failing closed.

    Returns the decision and, when the policy could not be applied, the error
    that prevented it (``None`` on success). Any exception -- from the policy,
    from its return value, or from a malformed result -- yields :data:`HIDDEN`:
    the caller learns nothing, including that the token exists. The caller logs
    the error; it must never fall back to disclosing the full response.
    """
    try:
        getter = getattr(policy, "get_visibility", None)
        if getter is not None:
            return _as_visibility(getter(context)), None
        active_getter = getattr(policy, "can_see_active", None)
        allow_active = True if active_getter is None else bool(active_getter(context))
        fields_getter = getattr(policy, "get_visible_fields", None)
        result = fields_getter(context) if fields_getter is not None else policy(context)
        if result is None:
            raise ValueError("a visibility policy must return fields or a visibility")
        if isinstance(result, dict):
            # A mapping decides presence per member, so it can also pick a different
            # allow_active than the policy object's own can_see_active().
            return _as_visibility(result), None
        if isinstance(result, IntrospectionVisibility) or (
            isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], bool)
        ):
            return _as_visibility(result), None
        return IntrospectionVisibility(allow_active=allow_active, fields=_as_fields(result)), None
    except Exception as exc:
        return HIDDEN, exc


__all__ = [
    "ACTIVE_ONLY",
    "AllFieldsPolicy",
    "CallerResourcePolicy",
    "EVERYTHING",
    "HIDDEN",
    "IntrospectionContext",
    "IntrospectionVisibility",
    "IntrospectionVisibilityPolicy",
    "VISIBLE_FIELDS",
    "evaluate_visibility",
    "resolve_visibility_policy",
]
