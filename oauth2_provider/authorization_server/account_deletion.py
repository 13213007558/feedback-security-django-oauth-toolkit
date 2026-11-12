"""Account erasure: revoke every OAuth credential, then delete the account.

Entry points
------------

* :func:`delete_account` -- the recommended integration point.  Called with a
  custom (or stock) user instance, it records and deletes every credential the
  authorization server issued to that account, then deletes the account row.
* :func:`resume_account_deletion` -- continues a job from its last committed
  checkpoint, including after the account row is already gone.

A plain ``user.delete()`` written elsewhere in the project is covered by the
``pre_delete``/``post_delete`` receivers in
:mod:`oauth2_provider.authorization_server.user_deletion_hooks`.

Why the order matters
---------------------

A bare ``user.delete()`` is not a safe erasure:

* ``AccessToken.user`` and ``IDToken.user`` are nullable.  A collector that is
  not allowed to cascade -- a database router, a swapped model with a different
  ``on_delete``, or a project that deletes through a restricted collector --
  can leave the row behind with the FK cleared.  ``AccessToken.user = NULL``
  is the exact shape of a client-credentials token: introspection omits
  ``username`` and bearer validation hands ``request.user = None`` to the
  resource server.  A user token whose owner was erased must therefore be
  refused by *credential identity*, not by the presence of a user.
* ``RefreshToken.user`` is ``CASCADE`` but ``RefreshToken.access_token`` is
  ``SET_NULL``.  If its access token goes first, the refresh token survives as
  a live orphan that can mint a new access token; if it goes through the
  collector, the refresh tombstone is the one credential row the collector
  does not remove.

The erasure therefore runs as committed checkpoints:

===  ======================  ================================================
#    State                   Work
===  ======================  ================================================
1    ``requested``           --
2    ``snapshotted``         One ledger row per credential: authorization
                             code, device grant, access token, refresh token,
                             ID token.  Digests and primary keys only, no
                             personal data.
3    ``credentials-revoked`` Every recorded credential row deleted, plus a
                             sweep for credentials minted since the snapshot
                             (a concurrent refresh).  Rows are addressed by
                             their recorded primary keys, never by the user FK.
4    ``account-erased``      The user row deleted.
5    ``completed``           The evidence purge deadline stamped.
===  ======================  ================================================

Each checkpoint commits separately, so a crash between any two leaves a row
that a later run continues from.  A deployment that must keep the account for a
retention period uses ``delete_account_row=False``: steps 1-3 run and the job
stops at ``credentials-revoked``; ``resume_account_deletion(job,
delete_account_row=True)`` later finishes steps 4-5.

The ledger outlives the job.  It is the bounded-lifetime evidence that refuses
a credential stranded by an interruption or by a previous, less careful
deletion; ``ACCOUNT_DELETION_REVOCATION_RETENTION_SECONDS`` bounds it and
``manage.py cleartokens`` purges it.
"""

import contextvars
import logging
from dataclasses import dataclass, field
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import router, transaction
from django.utils import timezone

from oauth2_provider.core.revocation import credential_digest
from oauth2_provider.models import (
    AccountDeletion,
    CredentialRevocation,
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")

# Set while service code performs the account delete itself, so the delete
# receivers know the job's checkpoint state, not a fresh snapshot, is in charge.
managed_erasure: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "oauth2_provider_managed_account_erasure", default=False
)

_CREDENTIAL_MODELS = {
    CredentialRevocation.KIND_AUTHORIZATION_CODE: get_grant_model,
    CredentialRevocation.KIND_DEVICE_GRANT: get_device_grant_model,
    CredentialRevocation.KIND_ACCESS_TOKEN: get_access_token_model,
    CredentialRevocation.KIND_REFRESH_TOKEN: get_refresh_token_model,
    CredentialRevocation.KIND_ID_TOKEN: get_id_token_model,
}


class AccountDeletionError(Exception):
    """Raised when an erasure cannot be started or resumed."""


@dataclass
class DeletionResult:
    """What :func:`delete_account` / :func:`resume_account_deletion` did."""

    deletion: AccountDeletion
    revoked: dict[str, int] = field(default_factory=dict)
    account_deleted: bool = False

    def __str__(self) -> str:
        parts = [f"{kind}={count}" for kind, count in sorted(self.revoked.items()) if count]
        parts.append("account deleted" if self.account_deleted else "account kept")
        return ", ".join(parts)


def account_label_for(model) -> str:
    return f"{model._meta.app_label}.{model._meta.model_name}"


def _retention_deadline(now):
    return now + timedelta(seconds=oauth2_settings.ACCOUNT_DELETION_REVOCATION_RETENTION_SECONDS)


def _value_digest(kind: str, row) -> str:
    """The ledger digest for one credential row.

    Access and refresh tokens already carry SHA-256 of the raw value in
    ``token_checksum``; the other kinds are digested here.  The raw credential
    is never written to the ledger.

    A ``RefreshToken`` is digestible even after rotation cleared its user
    relation, and the stock model always has a checksum.  A row whose plaintext
    was redacted (RFC 9700 storage) keeps its checksum too, so this never needs
    the raw value.
    """
    if kind in (CredentialRevocation.KIND_ACCESS_TOKEN, CredentialRevocation.KIND_REFRESH_TOKEN):
        return row.token_checksum
    if kind == CredentialRevocation.KIND_AUTHORIZATION_CODE:
        return credential_digest(row.code)
    if kind == CredentialRevocation.KIND_DEVICE_GRANT:
        return credential_digest(row.device_code)
    if kind == CredentialRevocation.KIND_ID_TOKEN:
        return credential_digest(str(row.jti))
    raise ValueError(f"unknown credential kind {kind!r}")


def _client_id_for_application(application_pk) -> str:
    if application_pk is None:
        return ""
    return (
        get_application_model().objects.filter(pk=application_pk).values_list("client_id", flat=True).first()
        or ""
    )


def _record(deletion: AccountDeletion, kind: str, digest: str, *, row, purge_after) -> bool:
    """Add one ledger entry; return whether it was newly created."""
    _, created = CredentialRevocation.objects.get_or_create(
        deletion=deletion,
        credential_kind=kind,
        credential_hash=digest,
        defaults={
            "object_pk": str(row.pk),
            "client_id": _client_id_for_application(getattr(row, "application_id", None))
            or getattr(row, "client_id", ""),
            "token_family": getattr(row, "token_family", None),
            "purge_after": purge_after,
        },
    )
    return created


def snapshot_credentials(deletion: AccountDeletion, user, *, now=None) -> dict[str, int]:
    """Record every credential owned by *user* in the ledger, before deleting any.

    Keyed on the user FK, so it must run before the account or any credential row
    is deleted.  Idempotent: entries are unique on
    ``(deletion, kind, credential_hash)``.
    """
    now = now or timezone.now()
    counts: dict[str, int] = {}
    purge_after = _retention_deadline(now)
    for kind, model_getter in _CREDENTIAL_MODELS.items():
        model = model_getter()
        recorded = 0
        for row in model.objects.filter(user=user).iterator():
            if _record(deletion, kind, _value_digest(kind, row), row=row, purge_after=purge_after):
                recorded += 1
        counts[kind] = recorded
    return counts


def delete_recorded_credentials(deletion: AccountDeletion) -> dict[str, int]:
    """Delete the credential rows named by the ledger.

    A row is deleted only when both its recorded primary key *and* its digest
    still match.  Primary keys can be reused (SQLite and any auto-increment
    field reuse the highest deleted key), so matching on the key alone could
    delete a later account's credential.  The digest was computed from the
    credential value, so a reuse with a different credential is left alone --
    correctly, because it is not the credential that was revoked.
    """
    counts: dict[str, int] = {}
    for kind, model_getter in _CREDENTIAL_MODELS.items():
        entries = {
            entry.object_pk: entry.credential_hash
            for entry in deletion.revocations.filter(credential_kind=kind).exclude(object_pk="")
        }
        if not entries:
            continue
        pks_to_delete = []
        for row in model_getter().objects.filter(pk__in=list(entries)):
            if _value_digest(kind, row) == entries[str(row.pk)]:
                pks_to_delete.append(row.pk)
        if pks_to_delete:
            deleted, _ = model_getter().objects.filter(pk__in=pks_to_delete).delete()
            counts[kind] = deleted
    return counts


def sweep_credentials_issued_since_snapshot(deletion: AccountDeletion, user, *, now=None) -> dict[str, int]:
    """Record and delete credentials minted after the snapshot.

    The account still has its user FK at this checkpoint, so a concurrent
    refresh that added a family member is found here.  Recording before deleting
    keeps the evidence complete even if the delete fails.
    """
    now = now or timezone.now()
    counts: dict[str, int] = {}
    purge_after = _retention_deadline(now)
    for kind, model_getter in _CREDENTIAL_MODELS.items():
        model = model_getter()
        recorded_hashes = set(
            deletion.revocations.filter(credential_kind=kind).values_list("credential_hash", flat=True)
        )
        pks = []
        for row in model.objects.filter(user=user).iterator():
            digest = _value_digest(kind, row)
            if digest not in recorded_hashes:
                _record(deletion, kind, digest, row=row, purge_after=purge_after)
                recorded_hashes.add(digest)
            pks.append(row.pk)
        if pks:
            deleted, _ = model.objects.filter(pk__in=pks).delete()
            counts[kind] = counts.get(kind, 0) + deleted
    return counts


def _find_user(deletion: AccountDeletion):
    """Return the account instance named by ``deletion.user_pk``, or ``None``."""
    user_model = get_user_model()
    try:
        return user_model._default_manager.get(pk=deletion.user_pk)
    except user_model.DoesNotExist:
        return None
    except (ValueError, TypeError):
        # A UUID primary key stored as text: the manager's field conversion may
        # reject the string on some backends, so compare textually.
        return user_model._default_manager.filter(pk=deletion.user_pk).first()


def _erase_account(user) -> None:
    """Delete the account row with the OAuth credential tables already handled.

    Django's collector still owns the project's other relations (sessions,
    profiles, ...); this function only guarantees that the account deletion is
    observed by the signal receivers as part of a managed erasure.
    """
    token = managed_erasure.set(True)
    try:
        user.delete()
    finally:
        managed_erasure.reset(token)


def _locked_job(pk) -> AccountDeletion:
    return AccountDeletion.objects.select_for_update().get(pk=pk)


def open_job(user_pk: str, account_model: str) -> AccountDeletion:
    """The newest job for *user_pk* that has not completed, or ``None``.

    ``user_pk`` can be reused by a later account when it is an auto-increment
    integer, so a completed job is deliberately not returned here: a live
    account at the same primary key needs its own erasure, not the previous
    account's journal row.
    """
    return (
        AccountDeletion.objects.filter(user_pk=str(user_pk), account_model=account_model)
        .exclude(state=AccountDeletion.STATE_COMPLETED)
        .order_by("-pk")
        .first()
    )


def _latest_completed_job(user_pk: str, account_model: str) -> AccountDeletion | None:
    return (
        AccountDeletion.objects.filter(
            user_pk=str(user_pk),
            account_model=account_model,
            state=AccountDeletion.STATE_COMPLETED,
        )
        .order_by("-pk")
        .first()
    )


def _advance(deletion: AccountDeletion) -> None:
    """Walk *deletion* through its remaining checkpoints, one commit at a time.

    Every step re-reads the row under a lock and is guarded by its expected
    state, so two workers resuming the same job do not repeat work and a crash
    between checkpoints resumes at the next one.
    """
    deletion.refresh_from_db()

    if deletion.state == AccountDeletion.STATE_REQUESTED:
        user = _find_user(deletion)
        if user is None:
            raise AccountDeletionError(
                f"AccountDeletion #{deletion.pk} is at 'requested' but the account "
                f"{deletion.user_pk!r} no longer exists, so no snapshot can be taken. "
                "Nothing has been revoked. Inspect the credential tables before retrying."
            )
        with transaction.atomic(using=router.db_for_write(AccountDeletion)):
            current = _locked_job(deletion.pk)
            if current.state == AccountDeletion.STATE_REQUESTED:
                now = timezone.now()
                current.summary = snapshot_credentials(current, user, now=now)
                current.snapshot_at = now
                current.state = AccountDeletion.STATE_SNAPSHOTTED
                current.save(update_fields=["summary", "snapshot_at", "state"])
        deletion.refresh_from_db()

    if deletion.state == AccountDeletion.STATE_SNAPSHOTTED:
        with transaction.atomic(using=router.db_for_write(AccountDeletion)):
            current = _locked_job(deletion.pk)
            if current.state == AccountDeletion.STATE_SNAPSHOTTED:
                now = timezone.now()
                counts = delete_recorded_credentials(current)
                user = _find_user(current)
                if user is not None:
                    for kind, n in sweep_credentials_issued_since_snapshot(current, user, now=now).items():
                        counts[kind] = counts.get(kind, 0) + n
                current.summary = {**(current.summary or {}), **counts}
                current.credentials_revoked_at = now
                current.state = AccountDeletion.STATE_CREDENTIALS_REVOKED
                current.save(update_fields=["summary", "credentials_revoked_at", "state"])
        deletion.refresh_from_db()

    if deletion.state == AccountDeletion.STATE_CREDENTIALS_REVOKED:
        if deletion.delete_account:
            with transaction.atomic(using=router.db_for_write(AccountDeletion)):
                current = _locked_job(deletion.pk)
                if current.state == AccountDeletion.STATE_CREDENTIALS_REVOKED and current.delete_account:
                    now = timezone.now()
                    user = _find_user(current)
                    if user is not None:
                        _erase_account(user)
                    current.account_erased_at = now
                    current.state = AccountDeletion.STATE_ACCOUNT_ERASED
                    current.save(update_fields=["account_erased_at", "state"])
            deletion.refresh_from_db()
        else:
            # Credentials-only mode: the OAuth side is finished.  The job is not
            # "completed" because a later resume may still erase the account; the
            # evidence deadline starts now either way.
            with transaction.atomic(using=router.db_for_write(AccountDeletion)):
                current = _locked_job(deletion.pk)
                if current.state == AccountDeletion.STATE_CREDENTIALS_REVOKED and not current.delete_account:
                    current.summary = {**(current.summary or {}), "account_kept": True}
                    current.completed_at = timezone.now()
                    current.revocation_purge_after = _retention_deadline(
                        current.credentials_revoked_at or timezone.now()
                    )
                    current.save(update_fields=["summary", "completed_at", "revocation_purge_after"])
            deletion.refresh_from_db()

    if deletion.state == AccountDeletion.STATE_ACCOUNT_ERASED:
        with transaction.atomic(using=router.db_for_write(AccountDeletion)):
            current = _locked_job(deletion.pk)
            if current.state == AccountDeletion.STATE_ACCOUNT_ERASED:
                now = timezone.now()
                current.state = AccountDeletion.STATE_COMPLETED
                current.completed_at = now
                current.revocation_purge_after = _retention_deadline(current.credentials_revoked_at or now)
                current.save(update_fields=["completed_at", "revocation_purge_after", "state"])
        deletion.refresh_from_db()


def delete_account(user, *, delete_account_row: bool = True) -> DeletionResult:
    """Revoke every OAuth credential of *user* and, by default, erase the account.

    Args:
        user: the account instance to erase.  Works for any ``AUTH_USER_MODEL``;
            only its primary key and model label are stored.
        delete_account_row: ``True`` also deletes the user row.  ``False``
            revokes and deletes every OAuth credential but keeps the account
            ("revoke now, erase later", for a deployment with its own retention
            policy).  The ledger is retained either way.

    Idempotent.  Calling it twice for the same account finds the existing job;
    a second call after completion does nothing.  A call for a *new* account
    that reused the same auto-increment primary key starts a fresh job rather
    than reusing the completed one, which would leave its credentials live.
    """
    if user is None or not getattr(user, "pk", None):
        raise AccountDeletionError("delete_account() needs a saved user instance.")

    label = account_label_for(type(user))
    with transaction.atomic(using=router.db_for_write(AccountDeletion)):
        deletion = open_job(user.pk, label)
        if deletion is None:
            completed = _latest_completed_job(user.pk, label)
            if completed is not None and _find_user(completed) is None:
                # Nothing has reused the primary key the completed job erased, so
                # this repeated call is a no-op.
                return DeletionResult(
                    deletion=completed,
                    revoked=completed.summary or {},
                    account_deleted=True,
                )
            # Either no job exists yet, or an auto-increment primary key has been
            # reused by a new account.  The second case must start a fresh job:
            # reusing the completed one would leave the new account's credentials
            # live.
            deletion = AccountDeletion.objects.create(
                user_pk=str(user.pk), account_model=label, delete_account=delete_account_row
            )
        else:
            deletion.delete_account = delete_account_row
            deletion.save(update_fields=["delete_account"])

    _advance(deletion)
    return DeletionResult(
        deletion=deletion,
        revoked=deletion.summary or {},
        account_deleted=deletion.account_erased_at is not None,
    )


def resume_account_deletion(
    deletion: AccountDeletion, *, delete_account_row: bool | None = None
) -> DeletionResult:
    """Continue an interrupted erasure from its last committed checkpoint.

    Args:
        deletion: the job row to continue.
        delete_account_row: override the job's flag; this is how a
            credentials-only job is completed with the account erased after the
            deployment's retention period.

    The account is looked up from ``user_pk``.  Once it is gone, the remaining
    work (credential cleanup and the evidence deadline) does not need it.
    """
    if delete_account_row is not None and deletion.delete_account != delete_account_row:
        deletion.delete_account = delete_account_row
        deletion.save(update_fields=["delete_account"])
        deletion.refresh_from_db()

    _advance(deletion)
    return DeletionResult(
        deletion=deletion,
        revoked=deletion.summary or {},
        account_deleted=deletion.account_erased_at is not None,
    )
