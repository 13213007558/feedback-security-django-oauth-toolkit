"""Bounded-lifetime credential revocation evidence.

Account erasure records every credential it revokes in
:class:`~oauth2_provider.models.CredentialRevocation` before deleting the row
(see :mod:`oauth2_provider.authorization_server.account_deletion`).  The
validation paths consult that ledger by credential digest, so a credential
stranded by an interrupted erasure -- most importantly an access token left with
``user = NULL`` by a ``SET_NULL`` custom model -- is refused instead of being
honored as a client-credentials token.

The raw credential is never stored: access and refresh tokens are keyed by the
``token_checksum`` the token models already keep, and the other kinds by
SHA-256 of their value.
"""

import hashlib

from django.utils import timezone

from oauth2_provider.models import CredentialRevocation


def credential_digest(value: str) -> str:
    """Return the SHA-256 hex digest the ledger stores for *value*."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def credential_revoked(kind: str, digest: str | None) -> bool:
    """Whether *digest* was revoked as a *kind* credential.

    A missing digest is never treated as revoked: a row without one cannot be
    looked up by its value either.  The evidence is purged after its retention
    window, by which time the credential rows themselves are gone.
    """
    if not digest:
        return False
    return CredentialRevocation.objects.filter(credential_kind=kind, credential_hash=digest).exists()


def is_access_token_revoked(token_checksum: str | None) -> bool:
    """Whether an access token with *token_checksum* was revoked by an erasure."""
    return credential_revoked(CredentialRevocation.KIND_ACCESS_TOKEN, token_checksum)


def is_refresh_token_revoked(token_checksum: str | None, token_family=None) -> bool:
    """Whether a refresh token, or any member of its family, was revoked by an erasure.

    A refresh token is keyed by its own digest.  ``token_family`` is also
    consulted because an erased account's whole rotation family is revoked as a
    unit: a rotated member that survived an interrupted deletion (a swapped
    model whose user FK is ``SET_NULL``) must not be exchangeable just because
    its own digest was not the one recorded.
    """
    if credential_revoked(CredentialRevocation.KIND_REFRESH_TOKEN, token_checksum):
        return True
    if token_family is None:
        return False
    return CredentialRevocation.objects.filter(
        credential_kind=CredentialRevocation.KIND_REFRESH_TOKEN,
        token_family=token_family,
    ).exists()


def is_userless_token_an_impersonation(application) -> bool:
    """Whether an ownerless token was issued to a client that only uses client credentials.

    ``user = NULL`` on an access token is the shape of a client-credentials
    token, so it cannot by itself prove an erasure.  It *is* anomalous when the
    token's client is not registered for the client-credentials grant: such a
    client only obtains tokens for a resource owner, so a userless token is a
    stranded user token (or a forgery) and must be refused rather than
    presented as a client identity.  ``application`` may be ``None``; a token
    without a client is never a legitimate client-credentials token either.
    """
    from oauth2_provider.models import AbstractApplication

    if application is None:
        return True
    return application.authorization_grant_type != AbstractApplication.GRANT_CLIENT_CREDENTIALS


def is_authorization_code_revoked(code: str | None) -> bool:
    """Whether an authorization code was revoked by an erasure."""
    if not code:
        return False
    return credential_revoked(CredentialRevocation.KIND_AUTHORIZATION_CODE, credential_digest(code))


def is_device_grant_revoked(device_code: str | None) -> bool:
    """Whether a device authorization grant was revoked by an erasure."""
    if not device_code:
        return False
    return credential_revoked(CredentialRevocation.KIND_DEVICE_GRANT, credential_digest(device_code))


def is_id_token_revoked(jti: str | None) -> bool:
    """Whether an ID token was revoked by an erasure."""
    if not jti:
        return False
    return credential_revoked(CredentialRevocation.KIND_ID_TOKEN, credential_digest(str(jti)))


def purge_revocation_evidence(*, at=None) -> int:
    """Delete ledger rows past their retention window; return the number deleted."""
    now = at or timezone.now()
    return CredentialRevocation.objects.filter(purge_after__lte=now).delete()[0]
