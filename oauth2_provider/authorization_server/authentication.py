"""Proof, supplied by the authentication system, of how and how recently the
end-user authenticated.

Some scopes should only be issued when the end-user's authentication is strong
enough and recent enough (a "stepped-up" authentication). What proves that is
the authentication system's business, never the client's: a self-reported
request parameter (``acr_values``, or any made-up parameter) is a statement of
preference, not proof. This module is the extension point between the two:

* the authentication system records a proof with
  :func:`record_authentication_proof` (the default backend keeps it in the
  Django session it authenticated, alongside the login records of
  :mod:`oauth2_provider.authorization_server.sessions`);
* the authorization server reads it back through the backend named by
  ``AUTHENTICATION_PROOF_BACKEND`` and checks it against
  ``SCOPE_AUTHENTICATION_REQUIREMENTS`` -- at the authorization endpoint
  (where an unmet requirement sends the user to re-authenticate), at
  authorization-code exchange and on every refresh (where an unmet
  requirement narrows the issued scopes).

A proof carries the level the authentication satisfied and the time it
happened. Both travel with the grant to the refresh token, so a refresh is
checked against the *original* authentication: a sensitive scope cannot be
kept alive forever by refreshing, because the proof behind it eventually
falls outside the required age.

All freshness checks read :func:`authentication_clock`, so tests and demos can
drive expiry with a controllable clock.
"""

from dataclasses import dataclass
from datetime import datetime
from datetime import timezone as datetime_timezone
from typing import Any

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils import timezone

from oauth2_provider.settings import oauth2_settings


#: Where the default backend keeps the proof: in the Django session whose
#: login it describes. Django's login() flushes or cycles the session before
#: the user_logged_in signal, and logout() flushes it, so a proof left behind
#: by a previous login never outlives the session it authenticated.
AUTHENTICATION_PROOF_SESSION_KEY = "_oauth2_provider_authentication_proof"


def authentication_clock() -> datetime:
    """The clock every authentication-proof freshness check reads.

    Separate from the token-expiry clock so a deployment (or a test) can
    control authentication freshness on its own.
    """
    return timezone.now()


@dataclass(frozen=True)
class AuthenticationProof:
    """How, and when, the end-user authenticated.

    :attr:`level` is one of ``AUTHENTICATION_PROOF_LEVELS`` and
    :attr:`authenticated_at` the time the authentication completed.
    """

    level: str
    authenticated_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """The JSON-safe shape stored on grants, refresh tokens and sessions."""
        return {
            "level": self.level,
            "authenticated_at": self.authenticated_at.timestamp(),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AuthenticationProof | None":
        """The proof a stored mapping describes, or ``None`` if it is malformed.

        Stored values round-trip through JSON and, for the session backend,
        through the session serializer, so anything unexpected is ignored
        rather than trusted.
        """
        if not isinstance(data, dict):
            return None
        level = data.get("level")
        authenticated_at = data.get("authenticated_at")
        if not isinstance(level, str) or not level:
            return None
        if not isinstance(authenticated_at, (int, float)) or isinstance(authenticated_at, bool):
            return None
        return cls(
            level=level,
            authenticated_at=datetime.fromtimestamp(authenticated_at, tz=datetime_timezone.utc),
        )


def record_authentication_proof(
    request: HttpRequest, level: str, authenticated_at: datetime | None = None
) -> None:
    """Record, for the default backend, that the current session's
    authentication satisfied ``level`` at ``authenticated_at`` (now, by
    default).

    This is the write side of the extension point: the authentication system
    calls it once it has verified the end-user -- after a password login, an
    MFA step-up, a WebAuthn ceremony -- with the level that verification
    warrants. ``level`` must be one of ``AUTHENTICATION_PROOF_LEVELS`` when
    that setting names the levels the deployment recognizes.
    """
    levels = oauth2_settings.AUTHENTICATION_PROOF_LEVELS
    if levels and level not in levels:
        raise ValueError(
            f"Authentication proof level {level!r} is not one of the configured "
            "AUTHENTICATION_PROOF_LEVELS."
        )
    if authenticated_at is None:
        authenticated_at = authentication_clock()
    proof = AuthenticationProof(level=level, authenticated_at=authenticated_at)
    request.session[AUTHENTICATION_PROOF_SESSION_KEY] = proof.to_dict()


class SessionAuthenticationProofBackend:
    """The default backend: the proof is read from the Django session.

    The session is server-side state written by the authentication system
    (see :func:`record_authentication_proof`), so the proof cannot be
    influenced by request parameters. Deployments that keep authentication
    state elsewhere (an MFA framework, a hardware-backed store) replace this
    via ``AUTHENTICATION_PROOF_BACKEND``.
    """

    def get_proof(self, request: HttpRequest) -> AuthenticationProof | None:
        """The proof recorded for the session of ``request``, or ``None``."""
        session = getattr(request, "session", None)
        if session is None:
            return None
        return AuthenticationProof.from_dict(session.get(AUTHENTICATION_PROOF_SESSION_KEY))


def get_authentication_proof(request: HttpRequest) -> AuthenticationProof | None:
    """The proof the configured backend reports for ``request``, or ``None``.

    Called with the Django request at the authorization endpoint. Nothing the
    client sent is consulted: a backend that derived the proof from request
    parameters would be accepting a self-reported value as proof.
    """
    backend = oauth2_settings.AUTHENTICATION_PROOF_BACKEND()
    return backend.get_proof(request)


@dataclass(frozen=True)
class ScopeAuthenticationRequirement:
    """What issuing a scope requires of the end-user's authentication.

    ``level`` names the weakest acceptable entry of
    ``AUTHENTICATION_PROOF_LEVELS``; ``max_age_seconds`` the oldest acceptable
    authentication. Either may be ``None`` to leave that dimension unchecked.
    """

    level: str | None = None
    max_age_seconds: int | None = None


def scope_authentication_requirements() -> dict[str, ScopeAuthenticationRequirement]:
    """The parsed ``SCOPE_AUTHENTICATION_REQUIREMENTS`` setting.

    Raises ``ImproperlyConfigured`` on a malformed entry, so a
    misconfiguration fails loudly rather than silently dropping a check.
    """
    configured = oauth2_settings.SCOPE_AUTHENTICATION_REQUIREMENTS
    if not configured:
        return {}
    if not isinstance(configured, dict):
        raise ImproperlyConfigured(
            "SCOPE_AUTHENTICATION_REQUIREMENTS must be a mapping of scope name to requirement."
        )
    levels = oauth2_settings.AUTHENTICATION_PROOF_LEVELS
    requirements = {}
    for scope, requirement in configured.items():
        if not isinstance(requirement, dict):
            raise ImproperlyConfigured(
                f"SCOPE_AUTHENTICATION_REQUIREMENTS[{scope!r}] must be a mapping "
                "with optional 'level' and 'max_age_seconds' keys."
            )
        unknown = set(requirement) - {"level", "max_age_seconds"}
        if unknown:
            raise ImproperlyConfigured(
                f"SCOPE_AUTHENTICATION_REQUIREMENTS[{scope!r}] has unknown keys: {sorted(unknown)}."
            )
        level = requirement.get("level")
        max_age_seconds = requirement.get("max_age_seconds")
        if level is not None:
            if not isinstance(level, str) or not level:
                raise ImproperlyConfigured(
                    f"SCOPE_AUTHENTICATION_REQUIREMENTS[{scope!r}]['level'] must be a non-empty string."
                )
            if level not in levels:
                raise ImproperlyConfigured(
                    f"SCOPE_AUTHENTICATION_REQUIREMENTS[{scope!r}] requires level {level!r}, "
                    "which is not one of AUTHENTICATION_PROOF_LEVELS."
                )
        if max_age_seconds is not None and (
            not isinstance(max_age_seconds, (int, float))
            or isinstance(max_age_seconds, bool)
            or max_age_seconds < 0
        ):
            raise ImproperlyConfigured(
                f"SCOPE_AUTHENTICATION_REQUIREMENTS[{scope!r}]['max_age_seconds'] "
                "must be a non-negative number."
            )
        requirements[scope] = ScopeAuthenticationRequirement(level=level, max_age_seconds=max_age_seconds)
    return requirements


def requirement_satisfied(
    requirement: ScopeAuthenticationRequirement,
    proof: AuthenticationProof | None,
    now: datetime | None = None,
) -> bool:
    """Whether ``proof`` meets ``requirement`` at ``now`` (the authentication clock).

    A requirement with a level or an age is unmet without a proof. A proof
    level the deployment does not recognize (not in
    ``AUTHENTICATION_PROOF_LEVELS``) never meets a level requirement.
    """
    if requirement.level is None and requirement.max_age_seconds is None:
        return True
    if proof is None:
        return False
    if requirement.level is not None:
        levels = oauth2_settings.AUTHENTICATION_PROOF_LEVELS
        if proof.level not in levels or levels.index(proof.level) < levels.index(requirement.level):
            return False
    if requirement.max_age_seconds is not None:
        if now is None:
            now = authentication_clock()
        # Compared as timestamps so an aware stored time and a naive clock (or
        # vice versa, e.g. USE_TZ off) cannot raise instead of failing closed.
        age = now.timestamp() - proof.authenticated_at.timestamp()
        if age > requirement.max_age_seconds:
            return False
    return True


def unsatisfied_scopes(
    scopes: list[str], proof: AuthenticationProof | dict | None, now: datetime | None = None
) -> list[str]:
    """The scopes of ``scopes`` whose authentication requirement ``proof`` does not meet.

    ``proof`` may be an :class:`AuthenticationProof`, its stored mapping form
    (as kept on a grant or refresh token), or ``None``. Scopes without a
    configured requirement are never listed.
    """
    requirements = scope_authentication_requirements()
    if not requirements:
        return []
    if now is None:
        now = authentication_clock()
    if proof is not None and not isinstance(proof, AuthenticationProof):
        proof = AuthenticationProof.from_dict(proof)
    return [
        scope
        for scope in scopes
        if scope in requirements and not requirement_satisfied(requirements[scope], proof, now)
    ]


def satisfied_scopes(
    scopes: list[str], proof: AuthenticationProof | dict | None, now: datetime | None = None
) -> list[str]:
    """The scopes of ``scopes`` that may be issued given ``proof``: every scope
    without a requirement, plus those whose requirement the proof meets."""
    unsatisfied = set(unsatisfied_scopes(scopes, proof, now))
    return [scope for scope in scopes if scope not in unsatisfied]
