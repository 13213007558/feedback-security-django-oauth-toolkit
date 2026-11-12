"""Tests for versioned data-usage consent.

The consent a resource owner gives is pinned to the exact terms version the
consent page displayed, and that version is carried onto the grant and every
token derived from it. A version change can never widen what existing tokens
may do: stale consents re-prompt (or fail ``prompt=none``), and, behind a
setting, stop the refresh chain.
"""

from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core import signing
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.authorization_server.consent import (
    BaseConsentBackend,
    StaticConsentBackend,
)
from oauth2_provider.authorization_server.views.base import CONSENT_VERSION_SALT
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_grant_model,
    get_refresh_token_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
DeviceGrant = get_device_grant_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


class StaticVersionBackend(BaseConsentBackend):
    """Reports a class-level version the tests can change between requests."""

    version = "v1"

    def get_consent_version(self, request, application=None):
        return self.version

    def is_consent_valid(self, consented_version, current_version, request=None, application=None):
        return consented_version == current_version


class RelaxedVersionBackend(StaticVersionBackend):
    """An older consent stays valid unless the terms moved past ``valid_until``."""

    version = "v2"
    valid_until = "v1"

    def is_consent_valid(self, consented_version, current_version, request=None, application=None):
        return consented_version == current_version or consented_version <= self.valid_until


CONSENT_SETTINGS = {
    **presets.DEFAULT_SCOPES_RW,
    "CONSENT_BACKEND_CLASS": "tests.test_consent_version.StaticVersionBackend",
}
RELAXED_SETTINGS = {
    **presets.DEFAULT_SCOPES_RW,
    "CONSENT_BACKEND_CLASS": "tests.test_consent_version.RelaxedVersionBackend",
}


@pytest.mark.usefixtures("oauth2_settings")
class BaseConsentTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("consent_user", "consent@example.com", "123456")
        cls.application = Application.objects.create(
            name="Consent Application",
            redirect_uris="http://example.org",
            user=cls.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        StaticVersionBackend.version = "v1"
        RelaxedVersionBackend.version = "v2"
        RelaxedVersionBackend.valid_until = "v1"
        self.client.login(username="consent_user", password="123456")

    def authorize_params(self):
        return {
            "client_id": self.application.client_id,
            "response_type": "code",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
        }

    def get_consent_page(self):
        return self.client.get(reverse("oauth2_provider:authorize"), data=self.authorize_params())

    def submit_consent(self, response, *, allow=True, version_override=None):
        """POST the hidden fields rendered on ``response`` back to the endpoint."""
        data = {
            key: ("" if value is None else value)
            for key, value in response.context["form"].initial.items()
        }
        data["allow"] = allow
        if version_override is not None:
            data["consent_version"] = signing.dumps(version_override, salt=CONSENT_VERSION_SALT)
        return self.client.post(reverse("oauth2_provider:authorize"), data=data)

    def exchange_code(self, code):
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

    def authorize_and_exchange(self):
        page = self.get_consent_page()
        assert page.status_code == 200
        response = self.submit_consent(page)
        assert response.status_code == 302
        code = parse_qs(urlparse(response["Location"]).query)["code"][0]
        token_response = self.exchange_code(code)
        assert token_response.status_code == 200
        return token_response.json(), code


@pytest.mark.usefixtures("oauth2_settings")
class TestStaticBackendDefaults(TestCase):
    """Without configuration the feature is invisible and never invalidates."""

    def test_default_backend_returns_empty_version(self):
        backend = StaticConsentBackend()
        self.assertEqual(backend.get_consent_version(None, None), "")
        self.assertTrue(backend.is_consent_valid("", "anything", None, None))

    @pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
    def test_no_version_recorded_without_configuration(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        user = UserModel.objects.create_user("plain_user", "plain@example.com", "123456")
        application = Application.objects.create(
            name="Plain Application",
            redirect_uris="http://plain.example.org",
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        self.client.force_login(user)
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": application.client_id,
                "response_type": "code",
                "state": "s",
                "scope": "read write",
                "redirect_uri": "http://plain.example.org",
                "allow": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        grant = Grant.objects.filter(application=application).latest("id")
        self.assertEqual(grant.consent_version, "")


@pytest.mark.oauth2_settings(CONSENT_SETTINGS)
class TestConsentVersionOnGrantAndTokens(BaseConsentTest):
    def test_consent_page_renders_current_version_signed(self):
        response = self.get_consent_page()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["consent_version"], "v1")
        signed = response.context["form"].initial["consent_version"]
        self.assertEqual(signing.loads(signed, salt=CONSENT_VERSION_SALT), "v1")
        self.assertContains(response, "v1")

    def test_grant_and_tokens_record_the_consented_version(self):
        page = self.get_consent_page()
        response = self.submit_consent(page)
        self.assertEqual(response.status_code, 302)
        code = parse_qs(urlparse(response["Location"]).query)["code"][0]
        # The authorization code is consumed (deleted) at exchange, so read the
        # grant before exchanging it.
        self.assertEqual(Grant.objects.get(code=code).consent_version, "v1")
        token_response = self.exchange_code(code)
        self.assertEqual(token_response.status_code, 200)
        tokens = token_response.json()
        access_token = AccessToken.objects.get(token=tokens["access_token"])
        self.assertEqual(access_token.consent_version, "v1")
        refresh_token = RefreshToken.objects.get(token=tokens["refresh_token"])
        self.assertEqual(refresh_token.consent_version, "v1")

    def test_version_change_after_page_open_blocks_stale_submission(self):
        page = self.get_consent_page()
        # The backend changes the terms while the page stays open (another tab,
        # a deploy): the hidden field still carries the version that was shown.
        StaticVersionBackend.version = "v2"
        response = self.submit_consent(page)
        # No grant is written and the page is re-rendered against the new terms.
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["consent_version"], "v2")
        self.assertEqual(Grant.objects.count(), 0)
        signed = response.context["form"].initial["consent_version"]
        self.assertEqual(signing.loads(signed, salt=CONSENT_VERSION_SALT), "v2")

        # Resubmitting the freshly rendered page consents to v2 and is recorded.
        accepted = self.submit_consent(response)
        self.assertEqual(accepted.status_code, 302)
        code = parse_qs(urlparse(accepted["Location"]).query)["code"][0]
        self.assertEqual(Grant.objects.get(code=code).consent_version, "v2")

    def test_two_tabs_keep_their_own_versions(self):
        first_tab = self.get_consent_page()
        StaticVersionBackend.version = "v2"
        second_tab = self.get_consent_page()

        # The older tab cannot smuggle its consent past the current terms.
        stale = self.submit_consent(first_tab)
        self.assertEqual(stale.status_code, 200)
        self.assertEqual(stale.context["consent_version"], "v2")
        self.assertEqual(Grant.objects.count(), 0)

        # The tab opened after the change authorizes directly.
        current = self.submit_consent(second_tab)
        self.assertEqual(current.status_code, 302)
        code = parse_qs(urlparse(current["Location"]).query)["code"][0]
        self.assertEqual(Grant.objects.get(code=code).consent_version, "v2")

    def test_tampered_signed_field_is_rejected(self):
        page = self.get_consent_page()
        data = {
            key: ("" if value is None else value)
            for key, value in page.context["form"].initial.items()
        }
        data["allow"] = True
        data["consent_version"] = "not-a-signed-value"
        response = self.client.post(reverse("oauth2_provider:authorize"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Grant.objects.count(), 0)

    def test_unsigned_field_is_rejected_when_versioning_is_active(self):
        page = self.get_consent_page()
        data = {
            key: ("" if value is None else value)
            for key, value in page.context["form"].initial.items()
        }
        data["allow"] = True
        data["consent_version"] = "v1"  # raw value, not signed
        response = self.client.post(reverse("oauth2_provider:authorize"), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Grant.objects.count(), 0)

    def test_denial_does_not_record_a_grant(self):
        page = self.get_consent_page()
        response = self.submit_consent(page, allow=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response["Location"])
        self.assertEqual(Grant.objects.count(), 0)


@pytest.mark.oauth2_settings(CONSENT_SETTINGS)
class TestConsentVersionSkipAndPromptNone(BaseConsentTest):
    def _seed_token(self, version: str):
        tokens, _code = self.authorize_and_exchange()
        access_token = AccessToken.objects.get(token=tokens["access_token"])
        if access_token.consent_version != version:
            access_token.consent_version = version
            access_token.save(update_fields=["consent_version"])
        return access_token

    def test_auto_skips_when_recorded_consent_is_current(self):
        self._seed_token("v1")
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={**self.authorize_params(), "approval_prompt": "auto"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("error", response["Location"])

    def test_auto_reprompts_when_recorded_consent_is_stale(self):
        self._seed_token("v1")
        StaticVersionBackend.version = "v2"
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={**self.authorize_params(), "approval_prompt": "auto"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["consent_version"], "v2")

    def test_prompt_none_returns_consent_required_when_stale(self):
        self._seed_token("v1")
        StaticVersionBackend.version = "v2"
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={**self.authorize_params(), "prompt": "none"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=consent_required", response["Location"])

    def test_skip_authorization_records_current_version(self):
        self.application.skip_authorization = True
        self.application.save(update_fields=["skip_authorization"])
        StaticVersionBackend.version = "v3"
        response = self.client.get(reverse("oauth2_provider:authorize"), data=self.authorize_params())
        self.assertEqual(response.status_code, 302)
        grant = Grant.objects.get(application=self.application)
        self.assertEqual(grant.consent_version, "v3")

    @pytest.mark.oauth2_settings(RELAXED_SETTINGS)
    def test_backend_controls_what_counts_as_compatible(self):
        # A v1 consent remains valid under the relaxed policy even though the
        # backend now serves v2, so auto-approval proceeds without re-prompt.
        self._seed_token("v1")
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={**self.authorize_params(), "approval_prompt": "auto"},
        )
        self.assertEqual(response.status_code, 302)

        # Once the policy itself retires v1, the same recorded consent no longer
        # covers the request and the user must consent again.
        RelaxedVersionBackend.valid_until = "v0"
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={**self.authorize_params(), "approval_prompt": "auto"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["consent_version"], "v2")


@pytest.mark.oauth2_settings(CONSENT_SETTINGS)
class TestConsentVersionRefresh(BaseConsentTest):
    def _tokens(self):
        tokens, _code = self.authorize_and_exchange()
        return tokens

    def _refresh(self, refresh_token_value):
        return post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token_value, "scope": "read write"},
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )

    def test_refresh_preserves_consent_version(self):
        tokens = self._tokens()
        refreshed = self._refresh(tokens["refresh_token"])
        self.assertEqual(refreshed.status_code, 200)
        body = refreshed.json()
        new_access = AccessToken.objects.get(token=body["access_token"])
        new_refresh = RefreshToken.objects.get(token=body["refresh_token"])
        self.assertEqual(new_access.consent_version, "v1")
        self.assertEqual(new_refresh.consent_version, "v1")

    def test_refresh_allowed_by_default_when_terms_change(self):
        # Without the enforcement flag a terms change does not break existing
        # refresh chains; the new token keeps the original consent pinned.
        tokens = self._tokens()
        StaticVersionBackend.version = "v2"
        refreshed = self._refresh(tokens["refresh_token"])
        self.assertEqual(refreshed.status_code, 200)
        body = refreshed.json()
        self.assertEqual(AccessToken.objects.get(token=body["access_token"]).consent_version, "v1")

    def test_refresh_rejected_when_enforcement_enabled_and_terms_change(self):
        self.oauth2_settings.CONSENT_VERSION_ENFORCE_ON_REFRESH = True
        tokens = self._tokens()
        StaticVersionBackend.version = "v2"
        refreshed = self._refresh(tokens["refresh_token"])
        self.assertEqual(refreshed.status_code, 400)
        self.assertEqual(refreshed.json()["error"], "invalid_grant")
        # The original tokens are untouched and still carry their own consent.
        self.assertTrue(
            AccessToken.objects.filter(token=tokens["access_token"], consent_version="v1").exists()
        )

    def test_refresh_succeeds_under_enforcement_when_version_unchanged(self):
        self.oauth2_settings.CONSENT_VERSION_ENFORCE_ON_REFRESH = True
        tokens = self._tokens()
        refreshed = self._refresh(tokens["refresh_token"])
        self.assertEqual(refreshed.status_code, 200)
        body = refreshed.json()
        self.assertEqual(AccessToken.objects.get(token=body["access_token"]).consent_version, "v1")

    def test_non_rotating_refresh_keeps_the_pinned_version(self):
        self.oauth2_settings.ROTATE_REFRESH_TOKEN = False
        tokens = self._tokens()
        refreshed = self._refresh(tokens["refresh_token"])
        self.assertEqual(refreshed.status_code, 200)
        body = refreshed.json()
        # The access token row is updated in place rather than recreated, and the
        # refresh token is reused; both keep the consent they were pinned to.
        self.assertEqual(AccessToken.objects.get(token=body["access_token"]).consent_version, "v1")
        self.assertEqual(RefreshToken.objects.get(token=body["refresh_token"]).consent_version, "v1")


@pytest.mark.oauth2_settings(CONSENT_SETTINGS)
class TestConsentVersionAdmin(BaseConsentTest):
    def test_consent_version_is_listed_and_searchable(self):
        from oauth2_provider.authorization_server import admin as oauth_admin

        cases = (
            (oauth_admin.AccessTokenAdmin, AccessToken),
            (oauth_admin.RefreshTokenAdmin, RefreshToken),
            (oauth_admin.GrantAdmin, Grant),
        )
        for admin_class, model in cases:
            model_admin = admin_class(model, oauth_admin.admin.site)
            self.assertIn("consent_version", model_admin.list_display)
            self.assertIn("consent_version", model_admin.search_fields)


@pytest.mark.oauth2_settings(CONSENT_SETTINGS)
class TestConsentVersionImplicit(BaseConsentTest):
    def test_implicit_token_pinned_to_consented_version(self):
        implicit_application = Application.objects.create(
            name="Implicit Consent Application",
            redirect_uris="http://implicit.example.org",
            user=self.test_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            client_secret=CLEARTEXT_SECRET,
        )
        params = {
            "client_id": implicit_application.client_id,
            "response_type": "token",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://implicit.example.org",
        }
        page = self.client.get(reverse("oauth2_provider:authorize"), data=params)
        self.assertEqual(page.status_code, 200)
        data = {
            key: ("" if value is None else value)
            for key, value in page.context["form"].initial.items()
        }
        data["allow"] = True
        response = self.client.post(reverse("oauth2_provider:authorize"), data=data)
        self.assertEqual(response.status_code, 302)
        fragment = urlparse(response["Location"]).fragment
        raw_token = parse_qs(fragment)["access_token"][0]
        access_token = AccessToken.objects.get(token=raw_token)
        self.assertEqual(access_token.consent_version, "v1")


@pytest.mark.oauth2_settings(CONSENT_SETTINGS)
class TestConsentVersionDeviceFlow(BaseConsentTest):
    """The device-confirm tab (browser side of RFC 8628) signs the version too."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.device_application = Application.objects.create(
            name="Device Consent Application",
            redirect_uris="",
            user=cls.test_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def _create_device(self, suffix: str):
        return DeviceGrant.objects.create(
            client_id=self.device_application.client_id,
            device_code=f"device-code-{suffix}",
            user_code=f"USER-CODE-{suffix}",
            scope="read write",
            expires=timezone.now() + timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZATION_PENDING,
            user=self.test_user,
        )

    def _confirm_url(self, device):
        return reverse(
            "oauth2_provider:device-confirm",
            kwargs={"client_id": self.device_application.client_id, "user_code": device.user_code},
        )

    def test_confirm_page_signs_version_and_approval_records_it(self):
        device = self._create_device("1")
        url = self._confirm_url(device)
        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.context["consent_version"], "v1")

        response = self.client.post(
            url,
            data={"action": "accept", "consent_version": page.context["consent_version_signed"]},
        )
        self.assertEqual(response.status_code, 302)
        device.refresh_from_db()
        self.assertEqual(device.status, device.AUTHORIZED)
        self.assertEqual(device.consent_version, "v1")

    def test_stale_device_consent_is_reprompted_not_recorded(self):
        device = self._create_device("2")
        url = self._confirm_url(device)
        page = self.client.get(url)
        StaticVersionBackend.version = "v2"
        response = self.client.post(
            url,
            data={"action": "accept", "consent_version": page.context["consent_version_signed"]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["consent_version"], "v2")
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceGrant.AUTHORIZATION_PENDING)
        self.assertEqual(device.consent_version, "")

        # Approving the re-rendered page records the current version.
        response = self.client.post(
            url,
            data={"action": "accept", "consent_version": response.context["consent_version_signed"]},
        )
        self.assertEqual(response.status_code, 302)
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceGrant.AUTHORIZED)
        self.assertEqual(device.consent_version, "v2")

    def test_tampered_device_consent_is_rejected(self):
        device = self._create_device("3")
        url = self._confirm_url(device)
        response = self.client.post(
            url,
            data={
                "action": "accept",
                "consent_version": "not-a-signed-value",
            },
        )
        # The form is invalid, so FormView re-renders the confirm page (200)
        # with a field error and the device stays pending, unversioned.
        self.assertEqual(response.status_code, 200)
        self.assertIn("consent_version", response.context["form"].errors)
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceGrant.AUTHORIZATION_PENDING)
        self.assertEqual(device.consent_version, "")

    def test_device_token_inherits_consent_version(self):
        # The token endpoint's device-code leg is blocked in this environment by
        # an oauthlib 4.x/validator mismatch unrelated to consent (the baseline
        # device tests fail on it too), so pin the inheritance contract at the
        # validator boundary that actually reads the approved grant.
        from oauthlib.common import Request as OauthlibRequest

        from oauth2_provider.oauth2_validators import GRANT_TYPE_DEVICE_CODE, OAuth2Validator

        device = self._create_device("4")
        device.status = DeviceGrant.AUTHORIZED
        device.consent_version = "v1"
        device.save(update_fields=["status", "consent_version"])

        oauthlib_request = OauthlibRequest("")
        oauthlib_request.grant_type = GRANT_TYPE_DEVICE_CODE
        oauthlib_request._params = {"device_code": device.device_code}
        self.assertEqual(OAuth2Validator()._consent_version_to_store(oauthlib_request), "v1")

        # And an unconsented (still pending, empty version) grant stays empty.
        pending = self._create_device("5")
        pending_request = OauthlibRequest("")
        pending_request.grant_type = GRANT_TYPE_DEVICE_CODE
        pending_request._params = {"device_code": pending.device_code}
        self.assertEqual(OAuth2Validator()._consent_version_to_store(pending_request), "")
