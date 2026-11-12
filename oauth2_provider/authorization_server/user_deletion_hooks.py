"""Delete-signal receivers that make a bare ``user.delete()`` safe.

``AccountDeletion`` is the durable journal; these receivers are the enforcement
layer for projects that erase an account through Django's ordinary
``user.delete()`` instead of calling
:func:`~oauth2_provider.authorization_server.account_deletion.delete_account`.

``pre_delete`` runs inside the caller's deletion transaction and snapshots the
account's credentials into the ledger *before* the collector runs, so a
nullable ``AccessToken.user`` the collector leaves behind with ``user = NULL``
is still refused by credential identity, and the ``RefreshToken`` tombstone the
collector would leave behind is recorded.  ``post_delete`` removes whatever
credential rows the collector left stranded, addressed through the ledger's
recorded primary keys, and stamps the job complete.

Both receivers are no-ops while
:data:`~oauth2_provider.authorization_server.account_deletion.managed_erasure`
is set: :func:`delete_account` already owns the checkpoint ordering then.

They create no job for a credential-less account, because there is nothing to
revoke (and deleting a fixture user during setup must not leave journal rows).
"""

import logging
import weakref

from django.contrib.auth import get_user_model
from django.db import router
from django.db.models.signals import post_delete, pre_delete
from django.utils import timezone

from oauth2_provider.authorization_server.account_deletion import (
    _CREDENTIAL_MODELS,
    account_label_for,
    delete_recorded_credentials,
    managed_erasure,
    open_job,
    snapshot_credentials,
)
from oauth2_provider.models import AccountDeletion


log = logging.getLogger("oauth2_provider")

_PRE_UID = "oauth2_provider_account_deletion_pre_delete"
_POST_UID = "oauth2_provider_account_deletion_post_delete"

# ``AccountDeletion.pk`` for the account instance whose pre_delete ran.  Weak
# keys: a stale entry cannot keep a deleted account alive, and it disappears
# with the object.  post_delete pops it.
_pending: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def connect(sender=None) -> None:
    """Connect both receivers to *sender* (default: ``AUTH_USER_MODEL``), once."""
    sender = sender or get_user_model()
    pre_delete.connect(_pre_delete_flag, sender=sender, dispatch_uid=_PRE_UID)
    post_delete.connect(_post_delete_flag, sender=sender, dispatch_uid=_POST_UID)


def disconnect(sender) -> None:
    pre_delete.disconnect(sender=sender, dispatch_uid=_PRE_UID)
    post_delete.disconnect(sender=sender, dispatch_uid=_POST_UID)


def _has_credentials(user) -> bool:
    return any(
        model_getter().objects.filter(user=user).exists() for model_getter in _CREDENTIAL_MODELS.values()
    )


def _pre_delete_flag(sender, instance, using, **kwargs) -> None:
    if managed_erasure.get() or instance.pk is None:
        return
    if not _has_credentials(instance):
        return
    journal_db = router.db_for_write(AccountDeletion, instance=instance) or using
    try:
        deletion = open_job(instance.pk, account_label_for(sender))
        if deletion is None:
            deletion = AccountDeletion.objects.using(journal_db).create(
                user_pk=str(instance.pk), account_model=account_label_for(sender)
            )
        if deletion.snapshot_at is None:
            now = timezone.now()
            deletion.summary = snapshot_credentials(deletion, instance, now=now)
            deletion.snapshot_at = now
            deletion.state = AccountDeletion.STATE_SNAPSHOTTED
            deletion.save(using=journal_db, update_fields=["summary", "snapshot_at", "state"])
        _pending[instance] = deletion.pk
    except Exception:
        # Never turn a legitimate account deletion into a 500: the account must
        # go.  The journal row (if one was created) remains for an operator to
        # resume, and the reason is logged.
        log.exception("Account-deletion guard could not snapshot credentials for %r", instance)
        _pending.pop(instance, None)


def _post_delete_flag(sender, instance, using, **kwargs) -> None:
    if managed_erasure.get():
        return
    deletion_pk = _pending.pop(instance, None)
    if deletion_pk is None:
        return
    journal_db = router.db_for_read(AccountDeletion, instance=instance) or using
    try:
        deletion = AccountDeletion.objects.using(journal_db).get(pk=deletion_pk)
        if deletion.state != AccountDeletion.STATE_SNAPSHOTTED:
            return
        now = timezone.now()
        counts = delete_recorded_credentials(deletion)
        deletion.summary = {**(deletion.summary or {}), **counts}
        deletion.credentials_revoked_at = now
        deletion.account_erased_at = now
        deletion.completed_at = now
        from oauth2_provider.authorization_server.account_deletion import _retention_deadline

        deletion.revocation_purge_after = _retention_deadline(now)
        deletion.state = AccountDeletion.STATE_COMPLETED
        deletion.save(
            using=journal_db,
            update_fields=[
                "summary",
                "credentials_revoked_at",
                "account_erased_at",
                "completed_at",
                "revocation_purge_after",
                "state",
            ],
        )
    except AccountDeletion.DoesNotExist:
        return
    except Exception:
        log.exception("Account-deletion guard could not finish revocation of deletion #%s", deletion_pk)
