"""Account-erasure integration tests.

Run under ``tests.settings_custom_user``: a real ``AUTH_USER_MODEL`` swap.
The ``SET_NULL`` credential shape is reproduced by clearing a token's ``user``
FK directly -- exactly the row state a collector leaves behind when a swapped
token model does not cascade.  That row has no owner, which introspection and
bearer validation would otherwise treat as a client-credentials token.
"""

import base64
import datetime
import hashlib
import json

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.authorization_server.account_deletion import (
    AccountDeletionError,
    delete_account,
    resume_account_deletion,
)
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

from . import presets
from .common_testing import OAuth2ProviderTransactionTestCase as TransactionTestCase
from .utils import get_basic_auth_header, post_form


# This module needs its own process-wide user model and installed app.  The
# default suite imports every test module, so skip cleanly there and run it in
# the dedicated tox cell (tests.settings_custom_user).
pytestmark = pytest.mark.skipif(
    settings.AUTH_USER_MODEL != "account_app.Account",
    reason="account-erasure tests run under tests.settings_custom_user",
)


Account = get_user_model()
Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
Grant = get_grant_model()
DeviceGrant = get_device_grant_model()
IDToken = get_id_token_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


def checksum(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({**presets.DEFAULT_SCOPES_RW, "PKCE_REQUIRED": False})
@pytest.mark.django_db(transaction=True)
class AccountDeletionBase(TransactionTestCase):
    def setUp(self):
        self.account = Account.objects.create_user("erased_user", "erased@example.com", "123456")
        self.other = Account.objects.create_user("other_user", "other@example.com", "123456")
        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://example.org",
            user=self.account,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            can_introspect=True,
        )
        # An introspection caller owned by another account, so deleting the
        # erased account (which cascades its own applications) cannot remove it.
        self.introspector = Application.objects.create(
            name="Introspector",
            redirect_uris="http://example.org",
            user=self.other,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            can_introspect=True,
        )

    def _issue_all_credentials(self):
        """Every credential kind the erasure must cover, owned by ``account``."""
        self.grant = Grant.objects.create(
            user=self.account,
            application=self.application,
            code="auth-code-value",
            expires=timezone.now() + datetime.timedelta(minutes=10),
            redirect_uri="http://example.org",
            scope="read write",
        )
        device = DeviceGrant.objects.create(
            user=self.account,
            device_code="device-code-value",
            user_code="USER-CODE",
            client_id=self.application.client_id,
            expires=timezone.now() + datetime.timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZED,
        )
        self.device = device
        access = AccessToken.objects.create(
            user=self.account,
            token="access-token-value",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read write",
        )
        refresh = RefreshToken.objects.create(
            user=self.account,
            token="refresh-token-value",
            application=self.application,
            access_token=access,
            token_family="8b2f7a52-6f5a-4a3e-9a4d-2a2f0e4b7c11",
            resource=[],
        )
        id_token = IDToken.objects.create(
            user=self.account,
            jti="5a7a0e5c-43a8-4b2f-8c04-9f3b3c1e2d44",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="openid",
        )
        self.access = access
        self.refresh = refresh
        self.id_token = id_token
        return access, refresh


class TestDeleteAccount(AccountDeletionBase):
    def test_delete_account_revokes_every_credential_kind(self):
        access, refresh = self._issue_all_credentials()

        result = delete_account(self.account)

        self.assertEqual(result.deletion.state, AccountDeletion.STATE_COMPLETED)
        self.assertTrue(result.account_deleted)
        self.assertFalse(Account.objects.filter(pk=self.account.pk).exists())

        # Access token: model rows deleted outright.
        self.assertFalse(AccessToken.objects.exists())
        # Refresh token: deleted, not left as a reuse tombstone.
        self.assertFalse(RefreshToken.objects.exists())
        # Authorization code, device grant and ID token rows are gone.
        self.assertFalse(Grant.objects.exists())
        self.assertFalse(DeviceGrant.objects.exists())
        self.assertFalse(IDToken.objects.exists())

        # One evidence row per credential, recording no personal data.
        kinds = set(
            CredentialRevocation.objects.filter(deletion=result.deletion).values_list(
                "credential_kind", flat=True
            )
        )
        self.assertEqual(
            kinds,
            {
                CredentialRevocation.KIND_AUTHORIZATION_CODE,
                CredentialRevocation.KIND_DEVICE_GRANT,
                CredentialRevocation.KIND_ACCESS_TOKEN,
                CredentialRevocation.KIND_REFRESH_TOKEN,
                CredentialRevocation.KIND_ID_TOKEN,
            },
        )
        self.assertEqual(CredentialRevocation.objects.count(), 5)
        evidence = CredentialRevocation.objects.filter(
            credential_kind=CredentialRevocation.KIND_ACCESS_TOKEN
        ).get()
        self.assertEqual(evidence.credential_hash, access.token_checksum)
        self.assertNotIn("access-token-value", evidence.credential_hash)
        self.assertEqual(evidence.client_id, self.application.client_id)

    def test_evidence_rows_hold_no_username_or_personal_data(self):
        self._issue_all_credentials()
        result = delete_account(self.account)
        deletion = result.deletion
        self.assertEqual(deletion.user_pk, str(self.account.pk))
        for value in (
            deletion.user_pk,
            deletion.account_model,
            deletion.summary,
        ):
            self.assertNotIn("erased_user", str(value))
        for entry in CredentialRevocation.objects.all():
            self.assertNotIn("erased_user", entry.client_id)
            self.assertNotIn("erased@example.com", str(entry.object_pk))

    def test_other_accounts_credentials_are_untouched(self):
        self._issue_all_credentials()
        other_app = Application.objects.create(
            name="Other Application",
            redirect_uris="http://example.org",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        other_token = AccessToken.objects.create(
            user=self.other,
            token="other-access-token",
            application=other_app,
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read write",
        )

        delete_account(self.account)

        self.assertFalse(Account.objects.filter(pk=self.account.pk).exists())
        self.assertTrue(Account.objects.filter(pk=self.other.pk).exists())
        self.assertTrue(AccessToken.objects.filter(pk=other_token.pk).exists())

    def test_delete_is_idempotent(self):
        self._issue_all_credentials()
        result = delete_account(self.account)
        self.assertEqual(result.deletion.state, AccountDeletion.STATE_COMPLETED)

        # The account is gone; a second call for the same instance is a no-op.
        result_again = delete_account(self.account)
        self.assertEqual(result_again.deletion.pk, result.deletion.pk)
        self.assertEqual(CredentialRevocation.objects.count(), 5)

    def test_credentials_only_mode_keeps_account_and_can_be_resumed(self):
        self._issue_all_credentials()

        result = delete_account(self.account, delete_account_row=False)

        self.assertEqual(result.deletion.state, AccountDeletion.STATE_CREDENTIALS_REVOKED)
        self.assertTrue(Account.objects.filter(pk=self.account.pk).exists())
        self.assertFalse(AccessToken.objects.exists())
        self.assertFalse(RefreshToken.objects.exists())
        self.assertFalse(Grant.objects.exists())
        # Evidence is already retained, so a leaked credential cannot be used
        # even though the account is still present.
        self.assertGreater(CredentialRevocation.objects.filter(deletion=result.deletion).count(), 0)

        # Finish the erasure after the deployment's retention period.
        resumed = resume_account_deletion(result.deletion, delete_account_row=True)
        self.assertEqual(resumed.deletion.state, AccountDeletion.STATE_COMPLETED)
        self.assertFalse(Account.objects.filter(pk=self.account.pk).exists())
        self.assertIsNotNone(resumed.deletion.revocation_purge_after)

    def test_delete_again_after_primary_key_is_reused_starts_a_new_job(self):
        self._issue_all_credentials()
        first = delete_account(self.account).deletion
        self.assertEqual(first.state, AccountDeletion.STATE_COMPLETED)

        # SQLite (and any auto-increment field) may reuse the highest deleted
        # primary key.  A new account at that key must get a new job, not the
        # completed one, or its credentials would never be revoked.
        reused = Account(username="reused_pk", email="reused@example.com")
        reused.set_password("123456")
        reused.pk = self.account.pk
        reused.save(force_insert=True)
        # The erased account's application was cascaded with it, so the new
        # account's credential needs its own client.
        reused_app = Application.objects.create(
            name="Reused Application",
            redirect_uris="http://example.org",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        RefreshToken.objects.create(
            user=reused,
            token="reused-refresh",
            application=reused_app,
            token_family="1b2f7a52-6f5a-4a3e-9a4d-2a2f0e4b7c12",
            resource=[],
        )

        second = delete_account(reused).deletion

        self.assertNotEqual(second.pk, first.pk)
        self.assertEqual(second.state, AccountDeletion.STATE_COMPLETED)
        self.assertFalse(RefreshToken.objects.exists())
        self.assertFalse(Account.objects.filter(pk=self.account.pk).exists())
        # The first job's evidence is untouched by the second job.
        self.assertEqual(CredentialRevocation.objects.filter(deletion=first).count(), 5)
        self.assertGreater(CredentialRevocation.objects.filter(deletion=second).count(), 0)

    def test_delete_without_any_credentials(self):
        account = Account.objects.create_user("bare_user", "bare@example.com", "123456")
        result = delete_account(account)
        self.assertEqual(result.deletion.state, AccountDeletion.STATE_COMPLETED)
        self.assertFalse(Account.objects.filter(pk=account.pk).exists())
        self.assertEqual(CredentialRevocation.objects.count(), 0)

    def test_delete_unsaved_user_is_refused(self):
        with self.assertRaises(AccountDeletionError):
            delete_account(Account(username="ghost"))

    def test_project_owned_profile_is_collected_and_deleted(self):
        from .account_app.models import AccountProfile

        AccountProfile.objects.create(account=self.account, display_name="Ada Lovelace")
        self._issue_all_credentials()

        delete_account(self.account)

        self.assertFalse(AccountProfile.objects.exists())


class TestResumeAfterInterruption(AccountDeletionBase):
    """A crash between checkpoints leaves a resumable journal row.

    Simulated by moving a job back to an earlier checkpoint, which is exactly
    the durable state a crash between commits leaves: the checked-in work is
    committed, later work is not.
    """

    def test_resume_finishes_after_snapshot_but_no_revocation(self):
        access, refresh = self._issue_all_credentials()

        deletion = AccountDeletion.objects.create(
            user_pk=str(self.account.pk),
            account_model="account_app.account",
            state=AccountDeletion.STATE_SNAPSHOTTED,
        )
        # The snapshot was committed before the crash.
        from oauth2_provider.authorization_server.account_deletion import snapshot_credentials

        deletion.summary = snapshot_credentials(deletion, self.account)
        deletion.snapshot_at = timezone.now()
        deletion.save()

        result = resume_account_deletion(deletion)

        self.assertEqual(result.deletion.state, AccountDeletion.STATE_COMPLETED)
        self.assertTrue(result.account_deleted)
        self.assertFalse(Account.objects.filter(pk=self.account.pk).exists())
        self.assertFalse(AccessToken.objects.exists())
        self.assertFalse(RefreshToken.objects.exists())

    def test_resume_after_account_already_erased_cleans_stranded_rows(self):
        # A ``SET_NULL`` access token survived an interrupted erasure: its
        # owner is gone, and without cleanup it looks like a client token.
        access, _refresh = self._issue_all_credentials()
        deletion = AccountDeletion.objects.create(
            user_pk=str(self.account.pk),
            account_model="account_app.account",
            state=AccountDeletion.STATE_SNAPSHOTTED,
        )
        from oauth2_provider.authorization_server.account_deletion import snapshot_credentials

        deletion.summary = snapshot_credentials(deletion, self.account)
        deletion.snapshot_at = timezone.now()
        deletion.save()
        # Simulate the crash: the account went away but only the collector ran.
        AccessToken.objects.filter(user=self.account).update(user=None)
        Account.objects.filter(pk=self.account.pk).delete()

        result = resume_account_deletion(deletion)

        self.assertEqual(result.deletion.state, AccountDeletion.STATE_COMPLETED)
        self.assertFalse(AccessToken.objects.exists())

    def test_resume_without_snapshot_and_account_gone_is_explicit(self):
        deletion = AccountDeletion.objects.create(
            user_pk=str(self.account.pk),
            account_model="account_app.account",
            state=AccountDeletion.STATE_REQUESTED,
        )
        Account.objects.filter(pk=self.account.pk).delete()

        with self.assertRaises(AccountDeletionError) as ctx:
            resume_account_deletion(deletion)
        self.assertIn("no snapshot", str(ctx.exception))


class TestIntrospectionAndBearerAfterErasure(AccountDeletionBase):
    """The acceptance criteria: no username residue, no client-identity fallback."""

    def test_introspection_reports_inactive_for_stranded_user_token(self):
        _access, _refresh = self._issue_all_credentials()
        # Erase every credential row except the access token, then clear its
        # owner: the exact shape an interrupted SET_NULL deletion leaves.
        AccessToken.objects.filter(user=self.account).update(user=None)
        Account.objects.filter(pk=self.account.pk).delete()

        self.client.login(username="other_user", password="123456")
        # Introspection requires an authorized client; use Basic auth of the app.
        credentials = base64.b64encode(f"{self.introspector.client_id}:{CLEARTEXT_SECRET}".encode()).decode()
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": "access-token-value"},
            HTTP_AUTHORIZATION="Basic " + credentials,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"active": False})

    def test_access_token_with_cleared_user_is_refused_by_bearer_validation(self):
        self._issue_all_credentials()
        token = AccessToken.objects.get(pk=self.access.pk)
        token.user = None
        token.save(update_fields=["user"])

        from oauthlib.common import Request as OauthlibRequest

        from oauth2_provider.oauth2_validators import OAuth2Validator

        validator = OAuth2Validator()
        request = OauthlibRequest("https://example.org/resource")
        # The live row is not revoked: a plain SET_NULL update, not an erasure.
        # It must still be refused, because a userless user token is not a
        # client-credentials token.
        self.assertFalse(validator.validate_bearer_token("access-token-value", ["read"], request))

    def test_erase_then_strand_rejects_both_paths(self):
        self._issue_all_credentials()
        deletion = delete_account(self.account, delete_account_row=False)
        # Post-erasure regression: recreate a row for the same credential with
        # a NULL user, as a buggy collector or a stale replica might.
        AccessToken.objects.create(
            user=None,
            token="access-token-value",
            application=self.application,
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read write",
        )
        self.assertTrue(
            CredentialRevocation.objects.filter(
                deletion=deletion.deletion,
                credential_kind=CredentialRevocation.KIND_ACCESS_TOKEN,
                credential_hash=checksum("access-token-value"),
            ).exists()
        )

        credentials = base64.b64encode(f"{self.introspector.client_id}:{CLEARTEXT_SECRET}".encode()).decode()
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": "access-token-value"},
            HTTP_AUTHORIZATION="Basic " + credentials,
        )
        self.assertEqual(response.json(), {"active": False})

        from oauthlib.common import Request as OauthlibRequest

        from oauth2_provider.oauth2_validators import OAuth2Validator

        validator = OAuth2Validator()
        request = OauthlibRequest("https://example.org/resource")
        self.assertFalse(validator.validate_bearer_token("access-token-value", ["read"], request))


class TestLiveOAuthFlowsAfterErasure(AccountDeletionBase):
    """End-to-end: real endpoints, real request parsing, erasure between them."""

    def _login(self, username="erased_user", password="123456"):
        self.client.login(username=username, password=password)

    def _authorize(self):
        data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=data)
        self.assertEqual(response.status_code, 302)
        from urllib.parse import parse_qs, urlparse

        return parse_qs(urlparse(response["Location"]).query)["code"].pop()

    def _exchange(self, code):
        return post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://example.org",
            },
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )

    def _refresh(self, refresh_token):
        return post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )

    def test_live_code_exchange_is_refused_after_erasure(self):
        self._login()
        code = self._authorize()
        self.assertTrue(Grant.objects.filter(code=code).exists())

        delete_account(self.account, delete_account_row=False)

        response = self._exchange(code)
        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid_grant", json.loads(response.content)["error"])

    def test_live_refresh_is_refused_after_erasure(self):
        self._login()
        code = self._authorize()
        token_response = self._exchange(code)
        self.assertEqual(token_response.status_code, 200)
        refresh_token = json.loads(token_response.content)["refresh_token"]

        delete_account(self.account, delete_account_row=False)

        response = self._refresh(refresh_token)
        self.assertEqual(response.status_code, 400)
        # RFC 6749 section 5.2: a refresh token that is no longer live is invalid_grant.
        self.assertEqual(json.loads(response.content)["error"], "invalid_grant")

    def test_live_device_poll_is_refused_after_erasure(self):
        device_app = Application.objects.create(
            name="Device Application",
            redirect_uris="http://example.org",
            user=self.account,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
        )
        DeviceGrant.objects.create(
            user=self.account,
            device_code="device-code-value",
            user_code="USER-CODE",
            client_id=device_app.client_id,
            expires=timezone.now() + datetime.timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZED,
        )

        delete_account(self.account, delete_account_row=False)

        # A stranded row with the same device_code and no owner, as a
        # non-cascading swapped DeviceGrant model would leave behind.
        DeviceGrant.objects.create(
            user=None,
            device_code="device-code-value",
            user_code="USER-CODE",
            client_id=device_app.client_id,
            expires=timezone.now() + datetime.timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZED,
        )

        response = post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": "device-code-value",
            },
            **get_basic_auth_header(device_app.client_id, ""),
        )
        # The ledger refuses the device_code before the row's state is even read,
        # so the stranded grant cannot be exchanged for a token.
        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid_grant", response.content.decode())


class TestDirectUserDeleteGuard(AccountDeletionBase):
    """A bare ``user.delete()`` written elsewhere must erase credentials too.

    The app config connects the receivers to ``AUTH_USER_MODEL``, so a project
    that deletes through the ordinary Django model delete gets the same
    guarantee without adopting ``delete_account()``.
    """

    def test_plain_user_delete_revokes_and_completes_a_job(self):
        self._issue_all_credentials()

        # A bare delete, as a project's admin view would do it.
        self.account.delete()

        self.assertFalse(Account.objects.filter(pk=self.account.pk).exists())
        self.assertFalse(AccessToken.objects.exists())
        self.assertFalse(RefreshToken.objects.exists())
        self.assertFalse(Grant.objects.exists())
        self.assertFalse(DeviceGrant.objects.exists())
        self.assertFalse(IDToken.objects.exists())

        job = AccountDeletion.objects.get()
        self.assertEqual(job.state, AccountDeletion.STATE_COMPLETED)
        self.assertIsNotNone(job.account_erased_at)
        self.assertIsNotNone(job.revocation_purge_after)
        self.assertEqual(job.revocations.count(), 5)

    def test_plain_delete_of_credentialless_account_leaves_no_journal(self):
        account = Account.objects.create_user("bare_user", "bare@example.com", "123456")
        account.delete()
        self.assertFalse(AccountDeletion.objects.exists())


class TestRevokedCredentialRefusal(AccountDeletionBase):
    def test_authorization_code_ledger_refuses_exchange(self):
        self._issue_all_credentials()
        delete_account(self.account, delete_account_row=False)
        self.assertTrue(
            CredentialRevocation.objects.filter(
                credential_kind=CredentialRevocation.KIND_AUTHORIZATION_CODE,
                credential_hash=checksum("auth-code-value"),
            ).exists()
        )

        from oauthlib.common import Request as OauthlibRequest

        from oauth2_provider.oauth2_validators import OAuth2Validator

        validator = OAuth2Validator()
        request = OauthlibRequest("https://example.org/token")
        self.assertFalse(
            validator.validate_code(self.application.client_id, "auth-code-value", self.application, request)
        )

    def test_device_code_ledger_refuses_token_exchange(self):
        self._issue_all_credentials()
        delete_account(self.account, delete_account_row=False)

        from oauth2_provider.oauth2_validators import OAuth2Validator

        validator = OAuth2Validator()
        self.assertIsNone(
            validator.validate_device_code(self.application.client_id, "device-code-value", request=None)
        )

    def test_refresh_family_is_refused_after_erasure(self):
        _access, refresh = self._issue_all_credentials()
        family = refresh.token_family
        delete_account(self.account, delete_account_row=False)

        # A rotated sibling that the deletion never saw directly (e.g. a
        # replica lag) is refused through the family recorded on the ledger.
        sibling = RefreshToken.objects.create(
            user=self.other,
            token="sibling-refresh-token",
            application=self.application,
            token_family=family,
            access_token=None,
            resource=[],
        )
        from oauth2_provider.core.revocation import is_refresh_token_revoked

        self.assertTrue(is_refresh_token_revoked(sibling.token_checksum, sibling.token_family))
        # And by its own evidence, the presented token is refused too.
        self.assertTrue(is_refresh_token_revoked(refresh.token_checksum))

    def test_evidence_is_purged_only_after_retention(self):
        self._issue_all_credentials()
        result = delete_account(self.account)
        deletion = result.deletion
        self.assertIsNotNone(deletion.revocation_purge_after)

        from oauth2_provider.core.revocation import purge_revocation_evidence

        self.assertEqual(
            purge_revocation_evidence(at=deletion.revocation_purge_after - datetime.timedelta(seconds=1)),
            0,
        )
        purged = purge_revocation_evidence(at=deletion.revocation_purge_after + datetime.timedelta(seconds=1))
        self.assertEqual(purged, 5)
        self.assertFalse(CredentialRevocation.objects.exists())
