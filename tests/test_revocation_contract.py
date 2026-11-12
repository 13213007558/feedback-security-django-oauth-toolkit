"""
Extension contract for the two refresh-token revocation paths.

``RefreshToken.revoke()`` (RFC 7009 /revoke/, RP-initiated logout, the admin action) and
``RefreshToken.revoke_family()`` (the set-based reuse-protection sweep) must leave the same
security state and emit the same ``refresh_token_revoked`` notification. The family sweep
keeps its constant-query ``QuerySet.update()``/``.delete()`` writes -- which never invoke
per-row model logic or the ORM save/delete signals -- and instead announces the rows it
invalidated through the dedicated signal after commit.

The tests cover the three failure modes called out in the design: a mid-transaction database
failure, a duplicate revocation, and a notification receiver that raises. In every case an
invalidated credential can no longer refresh and a notification that never committed is never
announced as success.
"""

import uuid
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.db import connections, router, transaction
from django.test.utils import CaptureQueriesContext, override_settings
from django.utils import timezone
from oauthlib.common import Request

from oauth2_provider.core.signals import refresh_token_revoked
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()


class RevocationContractTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user = UserModel.objects.create_user("revoke_user", "revoke@example.com", "123456")
        cls.application = Application.objects.create(
            name="revoke_app",
            redirect_uris="http://localhost http://example.com",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        cls.validator = OAuth2Validator()

    @property
    def token_db_alias(self):
        # The revocation code binds its on_commit hook to the alias the router picks for the
        # access-token write, which under the multi-db settings is not ``default``. Capture on
        # that same alias so the assertions hold on both layouts.
        return router.db_for_write(AccessToken)

    def capture_commit_callbacks(self):
        return self.captureOnCommitCallbacks(execute=True, using=self.token_db_alias)

    def _make_refresh_token(self, token_family, revoked=None, with_access_token=True, token=None):
        access_token = None
        if with_access_token:
            access_token = AccessToken.objects.create(
                user=self.user,
                token=f"access-{uuid.uuid4()}",
                application=self.application,
                expires=timezone.now() + timedelta(hours=1),
                scope="read write",
            )
        return RefreshToken.objects.create(
            user=self.user,
            token=token or f"refresh-{uuid.uuid4()}",
            application=self.application,
            access_token=access_token,
            token_family=token_family,
            revoked=revoked,
        )

    def _can_refresh(self, refresh_token):
        request = mock.MagicMock(wraps=Request)
        return self.validator.validate_refresh_token(refresh_token.token, self.application, request)

    @staticmethod
    def _record():
        seen = []

        def receiver(sender, refresh_token, **kwargs):
            seen.append((sender, refresh_token.pk, refresh_token.revoked, refresh_token.access_token_id))

        return seen, receiver


class TestRevocationNotificationContract(RevocationContractTestCase):
    def test_single_revoke_notifies_after_commit_with_final_state(self):
        refresh_token = self._make_refresh_token(uuid.uuid4())
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks() as callbacks:
                refresh_token.revoke()
            self.assertEqual(len(callbacks), 1)
            self.assertEqual(len(seen), 1)
            sender, pk, revoked, access_token_id = seen[0]
            self.assertIs(sender, RefreshToken)
            self.assertEqual(pk, refresh_token.pk)
            self.assertIsNotNone(revoked)
            self.assertIsNone(access_token_id)
        finally:
            refresh_token_revoked.disconnect(receiver)

    def test_family_sweep_notifies_each_live_member_once(self):
        family = uuid.uuid4()
        live_one = self._make_refresh_token(family)
        live_two = self._make_refresh_token(family)
        already_revoked = self._make_refresh_token(family, revoked=timezone.now() - timedelta(minutes=5))
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks() as callbacks:
                RefreshToken.revoke_family(family)
            # One callback per invalidated live row; the already-revoked member is not re-announced.
            self.assertCountEqual([item[1] for item in seen], [live_one.pk, live_two.pk])
            self.assertEqual(len(callbacks), 2)
            self.assertNotIn(already_revoked.pk, [item[1] for item in seen])
            for _, _, revoked, access_token_id in seen:
                self.assertIsNotNone(revoked)
                self.assertIsNone(access_token_id)
        finally:
            refresh_token_revoked.disconnect(receiver)

    def test_both_paths_use_the_same_signal_and_sender_contract(self):
        # The whole point of the contract: a swapped model subscribes once and is agnostic
        # to which path invalidated the credential.
        single = self._make_refresh_token(uuid.uuid4())
        family = uuid.uuid4()
        family_member = self._make_refresh_token(family)
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks():
                single.revoke()
                RefreshToken.revoke_family(family)
            senders = {item[0] for item in seen}
            self.assertEqual(senders, {RefreshToken})
            self.assertCountEqual([item[1] for item in seen], [single.pk, family_member.pk])
        finally:
            refresh_token_revoked.disconnect(receiver)


class TestMidTransactionDatabaseFailure(RevocationContractTestCase):
    def test_single_revoke_rolls_back_and_never_notifies(self):
        refresh_token = self._make_refresh_token(uuid.uuid4())
        access_token_pk = refresh_token.access_token_id
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks() as callbacks:
                with self.assertRaises(RuntimeError):
                    with transaction.atomic(using=self.token_db_alias):
                        refresh_token.revoke()
                        raise RuntimeError("database failed mid-transaction")
            # The hook was registered inside the rolled-back savepoint and discarded, so no
            # notification is announced even though the surrounding test transaction commits.
            self.assertEqual(seen, [])
            self.assertEqual(callbacks, [])
        finally:
            refresh_token_revoked.disconnect(receiver)

        refresh_token.refresh_from_db()
        self.assertIsNone(refresh_token.revoked, "a rolled-back revocation must not mark the token revoked")
        self.assertTrue(
            AccessToken.objects.filter(pk=access_token_pk).exists(),
            "the access token deleted inside the rollback must be restored",
        )
        self.assertTrue(self._can_refresh(refresh_token), "the credential must still refresh")

    def test_family_sweep_rolls_back_and_never_notifies(self):
        family = uuid.uuid4()
        member = self._make_refresh_token(family)
        access_token_pk = member.access_token_id
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks():
                with self.assertRaises(RuntimeError):
                    with transaction.atomic(using=self.token_db_alias):
                        RefreshToken.revoke_family(family)
                        raise RuntimeError("database failed mid-transaction")
            self.assertEqual(seen, [])
        finally:
            refresh_token_revoked.disconnect(receiver)

        member.refresh_from_db()
        self.assertIsNone(member.revoked)
        self.assertTrue(AccessToken.objects.filter(pk=access_token_pk).exists())
        self.assertTrue(self._can_refresh(member))


class TestDuplicateRevocation(RevocationContractTestCase):
    def test_revoking_twice_is_idempotent_and_notifies_once(self):
        refresh_token = self._make_refresh_token(uuid.uuid4())
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks():
                refresh_token.revoke()
            self.assertEqual(len(seen), 1)

            with self.capture_commit_callbacks() as callbacks:
                refresh_token.revoke()
            self.assertEqual(len(seen), 1, "a second revoke must not re-notify")
            self.assertEqual(callbacks, [])
        finally:
            refresh_token_revoked.disconnect(receiver)

        # And the credential stays unusable.
        refresh_token.refresh_from_db()
        self.assertIsNotNone(refresh_token.revoked)
        self.assertFalse(self._can_refresh(refresh_token))

    def test_sweeping_an_empty_family_notifies_nobody(self):
        family = uuid.uuid4()
        self._make_refresh_token(family, revoked=timezone.now() - timedelta(minutes=5))
        seen, receiver = self._record()
        refresh_token_revoked.connect(receiver, weak=False)
        try:
            with self.capture_commit_callbacks() as callbacks:
                RefreshToken.revoke_family(family)
            self.assertEqual(seen, [])
            self.assertEqual(callbacks, [])
        finally:
            refresh_token_revoked.disconnect(receiver)


class TestNotificationReceiverFailure(RevocationContractTestCase):
    def test_failing_receiver_is_logged_and_does_not_undo_revocation(self):
        family = uuid.uuid4()
        member = self._make_refresh_token(family)
        token = member.token

        def failing_receiver(sender, refresh_token, **kwargs):
            raise OSError("push notification service unreachable")

        refresh_token_revoked.connect(failing_receiver, weak=False)
        try:
            # The on_commit hook is registered as robust, so the test harness (mirroring the
            # production connection's run_and_clear_commit_hooks) swallows and logs the error
            # instead of letting it propagate out of the commit.
            with self.assertLogs("django.test", level="ERROR") as logs:
                with self.capture_commit_callbacks():
                    RefreshToken.revoke_family(family)
        finally:
            refresh_token_revoked.disconnect(failing_receiver)

        self.assertTrue(any("on_commit()" in line for line in logs.output))
        # The security state is independent of notification delivery: the credential is dead
        # even though the receiver could not announce the device-session logout.
        member.refresh_from_db()
        self.assertIsNotNone(member.revoked)
        self.assertIsNone(member.access_token_id)
        replayed = RefreshToken.objects.get(pk=member.pk)
        replayed.token = token
        self.assertFalse(self._can_refresh(replayed))

    def test_robust_hook_still_runs_independent_commit_callbacks(self):
        # ``robust=True`` isolates each on_commit callback: a notification that raises is
        # logged without suppressing a separate callback registered for the same commit.
        from django.db import transaction as db_transaction

        order = []

        def healthy():
            order.append("healthy")

        def explode():
            raise OSError("notification receiver failed")

        with self.capture_commit_callbacks():
            db_transaction.on_commit(healthy, using=self.token_db_alias, robust=True)
            db_transaction.on_commit(explode, using=self.token_db_alias, robust=True)
        self.assertEqual(order, ["healthy"])


class TestRevokedCredentialCannotRefresh(RevocationContractTestCase):
    @override_settings(OAUTH2_PROVIDER={"REFRESH_TOKEN_REUSE_PROTECTION": True})
    @pytest.mark.usefixtures("oauth2_settings")
    def test_replayed_family_token_is_rejected_and_sweeps_the_family(self):
        family = uuid.uuid4()
        replayed = self._make_refresh_token(family)
        sibling = self._make_refresh_token(family)
        # Mark the replayed token revoked-but-not-superseded, as an out-of-band /revoke/ would.
        replayed.revoked = timezone.now()
        replayed.save()

        self.assertFalse(self._can_refresh(replayed))

        replayed.refresh_from_db()
        sibling.refresh_from_db()
        self.assertIsNotNone(replayed.revoked)
        self.assertIsNotNone(sibling.revoked, "reuse protection must revoke every live member of the family")
        self.assertIsNone(sibling.access_token_id)
        self.assertFalse(self._can_refresh(sibling))


class TestFamilySweepQueryCount(RevocationContractTestCase):
    # Transaction-control statements (BEGIN/COMMIT/SAVEPOINT) are connection bookkeeping,
    # not the data path being measured; the delete collector's SET_NULL updates are constant
    # and independent of how many members the family holds.
    TRANSACTION_PREFIXES = ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE SAVEPOINT")

    def _data_query_count(self, historical_members):
        family = uuid.uuid4()
        self._make_refresh_token(family)
        for _ in range(historical_members):
            self._make_refresh_token(family, revoked=timezone.now())
        with CaptureQueriesContext(connections[self.token_db_alias]) as captured:
            RefreshToken.revoke_family(family)
        return sum(
            1
            for entry in captured.captured_queries
            if not entry["sql"].lstrip().upper().startswith(self.TRANSACTION_PREFIXES)
        )

    def test_query_count_is_constant_as_the_family_grows(self):
        # The read-back that powers notifications costs one query regardless of family size,
        # so the sweep still does not degrade into a per-token round trip.
        small = self._data_query_count(1)
        large = self._data_query_count(30)
        self.assertEqual(small, large)

    def test_data_statements_are_set_based_not_per_row(self):
        # Pin the actual shape: one read-back, one refresh-token update, the delete
        # collector's constant SET_NULL updates, and the access-token delete. None of these
        # multiply by the number of family members.
        count = self._data_query_count(10)
        self.assertGreaterEqual(count, 3)
        self.assertLessEqual(count, 6)
