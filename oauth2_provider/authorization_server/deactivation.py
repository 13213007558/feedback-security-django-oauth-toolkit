"""Reversible client deactivation for the authorization server.

Deactivation is an operator action: a client must stop obtaining new
authorizations immediately, while every row that already exists is kept so the
incident can be investigated. It is deliberately *not* a delete.

Two mechanisms carry the boundary:

``Application.deactivated_at``
    The operational flag. While it is set, the client cannot authenticate, start
    or approve an authorization request, redeem a code, poll a device grant,
    refresh, or use an access token. Clearing it (:func:`reactivate_application`)
    makes the client usable again.

``Application.authorization_generation``
    A monotonic counter bumped by deactivation. Every code, access token, refresh
    token and ID token records the generation current when it was minted. A
    credential minted under an older generation stays dead forever, even after
    the client is reactivated. That is what keeps a reactivation from silently
    restoring authorizations withdrawn during the deactivation window.

The rows this module withdraws are tombstoned rather than deleted: authorization
codes and tokens get ``revoked_at``/``revocation_reason``, stored authorization
requests get ``revoked_at``, and device grants move to ``DENIED``. They are still
present for an investigation, and the existing ``cleartokens`` retention policy
eventually reclaims them by expiry.

Transaction scope
-----------------
:func:`deactivate_application` performs the state change and the withdrawal of
visible credentials in one database transaction, taking the application row
lock first. The issuance paths take the same application row lock before they
write anything (see :func:`lock_application_for_issuance`), so on a database
whose row locks are honored (PostgreSQL, MySQL/InnoDB, Oracle) the two
serialize: an issuance either completes before the deactivation starts and is
swept by it, or starts after the deactivation commits and is refused.

This is a single-database guarantee. If the application row and the credential
rows live on different databases (a multi-database router), the transaction
cannot span them; the generation fence still refuses credentials minted under
an old generation, but the withdrawal itself is not one atomic unit. SQLite
ignores ``SELECT ... FOR UPDATE``; the tests use explicit interleaving points to
exercise the check ordering, and a passing SQLite test is not evidence of the
lock behavior of a production database.
"""

from dataclasses import dataclass
from typing import Optional

from django.db import router, transaction
from django.utils import timezone

from oauth2_provider.models import (
    AbstractApplication,
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
    get_stored_authorization_request_model,
)


DEACTIVATION_REASON = "client_deactivated"


@dataclass(frozen=True)
class DeactivationSummary:
    """What one deactivation/reactivation call changed.

    The counts let an operator confirm what was withdrawn. They are zero on a
    call that found the client already in the requested state.
    """

    application: AbstractApplication
    changed: bool
    grants_revoked: int = 0
    stored_requests_revoked: int = 0
    device_grants_denied: int = 0
    refresh_tokens_revoked: int = 0
    access_tokens_revoked: int = 0
    id_tokens_revoked: int = 0


def _database_for(application: AbstractApplication) -> str:
    """Return the database the application row (and its credentials) live on."""
    return application._state.db or router.db_for_write(get_application_model())


def _model_database(model) -> str:
    """Return the write database for a (possibly swapped) credential model."""
    return router.db_for_write(model)


def deactivate_application(application: AbstractApplication, *, reason: str = "") -> DeactivationSummary:
    """Deactivate *application* and withdraw the credentials it can still use.

    The application row is locked first, so an issuance path that took the same
    lock either finished (and its rows are swept here) or has not started yet
    (and will find the client inactive). Repeated calls are idempotent and do not
    bump the generation again.

    ``reason`` is stored on the application (truncated to the field size) and on
    every refresh/access token withdrawn here, so an investigation can tell a
    deactivation revocation from an ordinary one.
    """
    app_model = get_application_model()
    using = _database_for(application)
    with transaction.atomic(using=using):
        locked = app_model.objects.using(using).select_for_update().get(pk=application.pk)
        if locked.is_deactivated():
            return DeactivationSummary(application=locked, changed=False)

        now = timezone.now()
        locked.deactivate(reason=reason)
        application.deactivated_at = locked.deactivated_at
        application.deactivation_reason = locked.deactivation_reason
        application.authorization_generation = locked.authorization_generation
        application.updated = locked.updated

        grant_model = get_grant_model()
        grants_revoked = (
            grant_model.objects.using(_model_database(grant_model))
            .filter(application=locked, revoked_at__isnull=True)
            .update(revoked_at=now, updated=now)
        )
        # Deliberately not consumed: the row remains, so the investigation can see
        # which request was open when the client was deactivated.
        stored_request_model = get_stored_authorization_request_model()
        stored_requests_revoked = (
            stored_request_model.objects.using(_model_database(stored_request_model))
            .filter(client_id=locked.client_id, revoked_at__isnull=True)
            .update(revoked_at=now)
        )

        device_model = get_device_grant_model()
        device_grants_denied = (
            device_model.objects.using(_model_database(device_model))
            .filter(client_id=locked.client_id)
            .exclude(status__in=[device_model.DENIED, device_model.EXPIRED])
            .update(status=device_model.DENIED, last_checked=now)
        )

        refresh_model = get_refresh_token_model()
        refresh_tokens_revoked = (
            refresh_model.objects.using(_model_database(refresh_model))
            .filter(application=locked, revoked__isnull=True)
            .update(revoked=now, updated=now, revocation_reason=DEACTIVATION_REASON)
        )

        access_model = get_access_token_model()
        access_tokens_revoked = (
            access_model.objects.using(_model_database(access_model))
            .filter(application=locked, revoked_at__isnull=True)
            .update(revoked_at=now, updated=now, revocation_reason=DEACTIVATION_REASON)
        )

        # Every credential model that supports revocation carries the tombstone
        # columns; a swapped model that does not was not migrated for this feature,
        # and silently skipping it would leave live credentials behind.
        id_model = get_id_token_model()
        id_tokens_revoked = (
            id_model.objects.using(_model_database(id_model))
            .filter(application=locked, revoked_at__isnull=True)
            .update(revoked_at=now, updated=now, revocation_reason=DEACTIVATION_REASON)
        )

    return DeactivationSummary(
        application=application,
        changed=True,
        grants_revoked=grants_revoked,
        stored_requests_revoked=stored_requests_revoked,
        device_grants_denied=device_grants_denied,
        refresh_tokens_revoked=refresh_tokens_revoked,
        access_tokens_revoked=access_tokens_revoked,
        id_tokens_revoked=id_tokens_revoked,
    )


def reactivate_application(application: AbstractApplication) -> DeactivationSummary:
    """Clear the deactivation flag without restoring anything withdrawn.

    Only :attr:`AbstractApplication.deactivated_at` is cleared. The generation
    stays at the value deactivation put it at, and no tombstoned credential is
    un-revoked, so the client must obtain fresh authorizations. Repeated calls
    are no-ops.
    """
    app_model = get_application_model()
    using = _database_for(application)
    with transaction.atomic(using=using):
        locked = app_model.objects.using(using).select_for_update().get(pk=application.pk)
        if not locked.is_deactivated():
            return DeactivationSummary(application=locked, changed=False)
        locked.reactivate()
        application.deactivated_at = None
        application.reactivated_at = locked.reactivated_at
        application.authorization_generation = locked.authorization_generation
        application.updated = locked.updated
    return DeactivationSummary(application=application, changed=True)


def lock_application_for_issuance(
    client_id: str, *, using: Optional[str] = None, expected_generation: Optional[int] = None
) -> AbstractApplication:
    """Lock the application row and return it, refusing a deactivated or stale client.

    Called inside an issuance transaction, before any credential row is written.
    Taking the same row lock :func:`deactivate_application` takes is what makes
    the boundary serializable on databases that honor it. The current row is
    re-read under the lock, so a client object loaded earlier in the request
    cannot hide a deactivation committed in between.

    ``expected_generation`` is checked when a credential (an authorization code or
    refresh token) names the generation it was minted under. A mismatch means the
    credential predates a deactivation boundary and must be refused even though
    the client may now be active again.

    Raises :class:`Application.DoesNotExist` when there is no such client, and
    :class:`ValueError` when the client is deactivated or the generation is stale;
    callers translate that into the appropriate OAuth error.
    """
    app_model = get_application_model()
    using = using or router.db_for_write(app_model)
    locked = app_model.objects.using(using).select_for_update().get(client_id=client_id)
    if locked.is_deactivated():
        raise ValueError("The client is deactivated.")
    if expected_generation is not None and not locked.has_current_authorization(expected_generation):
        raise ValueError("The credential predates the client's current authorization generation.")
    return locked
