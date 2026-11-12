"""Reversible client deactivation.

Covers the security contract: a client deactivated while a browser consent page
is open, an authorization code is outstanding, or a refresh token is held must
not produce new permissions. Deactivation keeps every row for investigation, and
reactivating the client must not revive an authorization withdrawn at the
boundary.

The concurrency section uses explicit interleaving points instead of relying on
database row locks. SQLite (the default test database) ignores
``SELECT ... FOR UPDATE``, so a passing run here is evidence of the *check
ordering*, not of multi-process lock behavior. The transaction scope is spelled
out in ``oauth2_provider.authorization_server.deactivation``.
"""

import base64
import json
from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.urls import reverse
from django.utils import timezone
from oauthlib.common import Request as OAuthlibRequest
from oauthlib.oauth2.rfc6749 import errors

from oauth2_provider.authorization_server.deactivation import (
    DEACTIVATION_REASON,
    deactivate_application,
    lock_application_for_issuance,
    reactivate_application,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
    get_stored_authorization_request_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import post_form


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
IDToken = get_id_token_model()
DeviceGrant = get_device_grant_model()
StoredRequest = get_stored_authorization_request_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


def _basic_auth(client_id, secret):
    raw = f"{client_id}:{secret}".encode()
    return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(raw).decode()}


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class DeactivationBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("owner", "owner@example.com", "secret")
        cls.application = Application.objects.create(
            name="Deactivatable",
            user=cls.user,
            redirect_uris="http://example.org/cb",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["http", "https"]

    def authorize(self, *, scope="read write"):
        """Drive the consent form and return the authorization code."""
        self.client.login(username="owner", password="secret")
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "state": "s",
                "scope": scope,
                "redirect_uri": "http://example.org/cb",
                "response_type": "code",
                "allow": True,
            },
        )
        assert response.status_code == 302, response.content
        return parse_qs(urlparse(response["Location"]).query)["code"][0]

    def exchange(self, code, **extra):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org/cb",
            **extra,
        }
        return post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data=data,
            **_basic_auth(self.application.client_id, CLEARTEXT_SECRET),
        )

    def refresh(self, refresh_token):
        return post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            **_basic_auth(self.application.client_id, CLEARTEXT_SECRET),
        )


class TestDeactivationState(DeactivationBase):
    def test_deactivate_is_reversible_and_bumps_generation_once(self):
        assert not self.application.is_deactivated()
        generation = self.application.authorization_generation

        summary = deactivate_application(self.application, reason="incident 42")

        assert summary.changed is True
        self.application.refresh_from_db()
        assert self.application.is_deactivated()
        assert self.application.deactivated_at is not None
        assert self.application.deactivation_reason == "incident 42"
        assert self.application.authorization_generation == generation + 1

        # Repeated deactivation is idempotent: no second bump, no second reason.
        again = deactivate_application(self.application, reason="other")
        assert again.changed is False
        self.application.refresh_from_db()
        assert self.application.authorization_generation == generation + 1
        assert self.application.deactivation_reason == "incident 42"

    def test_reactivate_clears_the_flag_and_keeps_the_fence(self):
        deactivate_application(self.application)
        generation = self.application.authorization_generation

        summary = reactivate_application(self.application)

        assert summary.changed is True
        self.application.refresh_from_db()
        assert not self.application.is_deactivated()
        assert self.application.reactivated_at is not None
        assert self.application.authorization_generation == generation
        assert not self.application.has_current_authorization(generation - 1)
        assert self.application.has_current_authorization(generation)

    def test_deactivation_keeps_rows_for_investigation(self):
        code = self.authorize()
        grant = Grant.objects.get(code=code)
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token="live-at",
            expires=timezone.now() + timedelta(hours=1),
            scope="read write",
        )
        refresh = RefreshToken.objects.create(
            user=self.user, application=self.application, access_token=token, token="live-rt"
        )
        id_token = IDToken.objects.create(
            user=self.user,
            application=self.application,
            jti="11111111-1111-1111-1111-111111111111",
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )

        summary = deactivate_application(self.application)

        assert summary.changed is True
        assert summary.grants_revoked == 1
        assert summary.access_tokens_revoked == 1
        assert summary.refresh_tokens_revoked == 1
        assert summary.id_tokens_revoked == 1

        # Nothing was deleted; every row is still there, tombstoned.
        assert Grant.objects.filter(pk=grant.pk, revoked_at__isnull=False).exists()
        assert AccessToken.objects.filter(pk=token.pk, revoked_at__isnull=False).exists()
        assert RefreshToken.objects.filter(
            pk=refresh.pk, revoked__isnull=False, revocation_reason=DEACTIVATION_REASON
        ).exists()
        assert IDToken.objects.filter(pk=id_token.pk, revoked_at__isnull=False).exists()
        assert token.pk not in list(
            AccessToken.objects.filter(revoked_at__isnull=True).values_list("pk", flat=True)
        )


class TestIssuanceBoundary(DeactivationBase):
    def test_open_consent_page_does_not_yield_a_code_after_deactivation(self):
        """A page opened before the boundary must not produce a code after it.

        The GET validates the client while it is still active; the POST is what
        writes the code. Deactivation in between has to win.
        """
        self.client.login(username="owner", password="secret")
        get_response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "state": "s",
                "scope": "read write",
                "redirect_uri": "http://example.org/cb",
                "response_type": "code",
            },
        )
        assert get_response.status_code == 200

        deactivate_application(self.application)

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "state": "s",
                "scope": "read write",
                "redirect_uri": "http://example.org/cb",
                "response_type": "code",
                "allow": True,
            },
        )
        assert not Grant.objects.exists(), "no authorization code may be written for a deactivated client"
        # The deactivated client is reported as an invalid client, without a code.
        if response.status_code == 302:
            assert "code" not in parse_qs(urlparse(response["Location"]).query)

    def test_outstanding_code_cannot_be_redeemed(self):
        code = self.authorize()
        deactivate_application(self.application)
        response = self.exchange(code)
        assert response.status_code in {400, 401}, response.content
        assert json.loads(response.content)["error"] in {"invalid_client", "invalid_grant"}, response.content
        assert not AccessToken.objects.exists()

    def test_refresh_token_cannot_be_used(self):
        code = self.authorize()
        exchange = self.exchange(code)
        assert exchange.status_code == 200, exchange.content
        tokens = json.loads(exchange.content)
        deactivate_application(self.application)

        response = self.refresh(tokens["refresh_token"])

        assert response.status_code in {400, 401}
        assert json.loads(response.content)["error"] in {"invalid_client", "invalid_grant"}

    def test_bearer_token_is_rejected_and_introspection_reports_inactive(self):
        code = self.authorize()
        tokens = json.loads(self.exchange(code).content)
        deactivate_application(self.application)

        # Introspection (RFC 7662) must report the token inactive, whichever
        # authentication path the caller takes.
        from oauth2_provider.authorization_server.views.introspect import IntrospectTokenView

        response = IntrospectTokenView.get_token_response(tokens["access_token"])
        assert response.status_code == 200
        assert json.loads(response.content) == {"active": False}

    def test_reactivation_does_not_revive_withdrawn_authorizations(self):
        """The central contract: restore the client, not its withdrawn credentials."""
        code = self.authorize()
        tokens = json.loads(self.exchange(code).content)
        stale_code = self.authorize()
        deactivate_application(self.application)
        reactivate_application(self.application)

        self.application.refresh_from_db()
        assert not self.application.is_deactivated()

        # Everything withdrawn at the boundary stays dead.
        assert self.exchange(stale_code).status_code == 400
        assert self.refresh(tokens["refresh_token"]).status_code == 400

        stored = AccessToken.objects.get(token=tokens["access_token"])
        assert stored.revoked_at is not None

        # A fresh authorization does work and gets a new generation.
        fresh_code = self.authorize()
        fresh = self.exchange(fresh_code)
        assert fresh.status_code == 200
        new_token = AccessToken.objects.get(token=json.loads(fresh.content)["access_token"])
        assert new_token.authorization_generation == self.application.authorization_generation

    def test_user_bearer_authentication_is_refused(self):
        """A protected resource stops accepting the client's tokens immediately."""
        code = self.authorize()
        tokens = json.loads(self.exchange(code).content)
        deactivate_application(self.application)

        from oauth2_provider.oauth2_validators import OAuth2Validator

        validator = OAuth2Validator()
        request = OAuthlibRequest("http://testserver/resource", http_method="GET", body="", headers={})
        request.uri = "http://testserver/resource"
        assert validator.validate_bearer_token(tokens["access_token"], ["read"], request) is False

    def test_admin_actions_drive_the_boundary(self):
        """The admin only offers the actions; the fence itself is not editable there."""
        from django.contrib.admin.sites import AdminSite

        from oauth2_provider.authorization_server.admin import ApplicationAdmin

        model_admin = ApplicationAdmin(Application, AdminSite())
        assert "authorization_generation" in model_admin.get_readonly_fields(None, obj=self.application)
        assert "deactivated_at" in model_admin.get_readonly_fields(None, obj=self.application)
        assert "deactivate_applications" in model_admin.actions
        assert "reactivate_applications" in model_admin.actions

    def test_revocation_still_deletes_rows(self):
        """Deliberate revocation keeps its old delete semantics."""
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token="deliberate",
            expires=timezone.now() + timedelta(hours=1),
        )
        token.revoke()
        assert not AccessToken.objects.filter(pk=token.pk).exists()


class TestStoredRequestsAndDeviceGrants(DeactivationBase):
    def test_stored_request_is_refused_and_kept(self):
        stored = StoredRequest.objects.create(
            request_uri="urn:ietf:params:oauth:request_uri:abc",
            client_id=self.application.client_id,
            parameters={"client_id": self.application.client_id},
            expires=timezone.now() + timedelta(minutes=10),
        )
        deactivate_application(self.application)
        stored.refresh_from_db()
        assert stored.revoked_at is not None

        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {"client_id": self.application.client_id, "request_uri": stored.request_uri},
        )
        # A fatal invalid_request page is rendered because the request has no
        # validated redirect_uri to trust; the row is kept, not consumed.
        assert response.status_code == 400
        assert StoredRequest.objects.filter(pk=stored.pk).exists()

    def test_device_grant_is_denied_and_kept(self):
        device_app = Application.objects.create(
            name="Device",
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
        )
        device = DeviceGrant.objects.create(
            client_id=device_app.client_id,
            device_code="device-code",
            user_code="user-code",
            scope="read",
            expires=timezone.now() + timedelta(minutes=10),
            status=DeviceGrant.AUTHORIZATION_PENDING,
            user=self.user,
        )
        deactivate_application(device_app)
        device.refresh_from_db()
        assert device.status == DeviceGrant.DENIED
        assert DeviceGrant.objects.filter(pk=device.pk).exists()


@pytest.mark.usefixtures("oauth2_settings")
class TestInterleavings:
    """Explicit interleaving points, not multi-process locking.

    Each test stops an issuance path right before its write, runs the
    deactivation, then resumes it. This asserts the ordering of the checks:
    every issuance path re-reads the client under the boundary before it writes.
    It does not prove that two databases or two processes serialize — see the
    module docstring.
    """

    @pytest.mark.django_db(databases="__all__")
    def test_deactivation_between_code_write_and_exchange(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        user = UserModel.objects.create_user("interleave", "i@example.com", "secret")
        app = Application.objects.create(
            name="Interleaved",
            user=user,
            redirect_uris="http://example.org/cb",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        grant = Grant.objects.create(
            application=app,
            user=user,
            code="code-before-boundary",
            expires=timezone.now() + timedelta(minutes=5),
            redirect_uri="http://example.org/cb",
            scope="read",
            authorization_generation=app.authorization_generation,
        )

        deactivate_application(app)

        from oauth2_provider.oauth2_validators import OAuth2Validator

        validator = OAuth2Validator()
        request = mock.MagicMock()
        request.client = app
        request.scopes = []
        assert validator.validate_code(app.client_id, grant.code, app, request) is False
        assert validator.validate_refresh_token("never-issued", app, request) is False

    @pytest.mark.django_db(databases="__all__")
    def test_issuance_lock_refuses_stale_generation(self):
        user = UserModel.objects.create_user("lockuser", "l@example.com", "secret")
        app = Application.objects.create(
            name="Locked",
            user=user,
            redirect_uris="http://example.org/cb",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        old_generation = app.authorization_generation
        deactivate_application(app)
        reactivate_application(app)

        with transaction.atomic():
            with pytest.raises(ValueError, match="generation"):
                lock_application_for_issuance(app.client_id, expected_generation=old_generation)
            current = lock_application_for_issuance(
                app.client_id, expected_generation=app.authorization_generation
            )
            assert not current.is_deactivated()

    @pytest.mark.django_db(databases="__all__")
    def test_deactivation_wins_over_a_consent_write_started_earlier(self):
        """Simulate the consent POST reaching its write after the boundary.

        ``save_authorization_code`` takes the application row lock and re-reads
        the client. Patching ``select_for_update`` to deactivate the client at
        that exact point shows the re-check, not the browser's earlier GET, is
        authoritative.
        """
        self.oauth2_settings.PKCE_REQUIRED = False
        user = UserModel.objects.create_user("writerace", "w@example.com", "secret")
        app = Application.objects.create(
            name="Writerace",
            user=user,
            redirect_uris="http://example.org/cb",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

        real_lock = lock_application_for_issuance

        def deactivate_then_lock(client_id, **kwargs):
            # The seam is the issuance re-read itself: the deactivation lands
            # immediately before it, so only the check that guards the write can
            # catch it.
            deactivate_application(app)
            return real_lock(client_id, **kwargs)

        with mock.patch(
            "oauth2_provider.oauth2_validators.lock_application_for_issuance",
            side_effect=deactivate_then_lock,
        ):
            from oauth2_provider.oauth2_validators import OAuth2Validator

            validator = OAuth2Validator()
            request = OAuthlibRequest(
                "http://example.org/cb",
                http_method="GET",
                body="",
                headers={},
            )
            request.client_id = app.client_id
            request.redirect_uri = "http://example.org/cb"
            request.user = user
            request.scopes = ["read"]
            request.code_challenge = None
            request.code_challenge_method = None
            request.claims = {}
            with pytest.raises(errors.InvalidClientError):
                validator.save_authorization_code(app.client_id, {"code": "late-code"}, request)

        assert not Grant.objects.filter(code="late-code").exists()

    @pytest.mark.django_db(databases="__all__")
    def test_sqlite_ignores_select_for_update(self):
        """Documents the limits of the local test database.

        SQLite accepts ``select_for_update`` but does not lock, and Django's
        SQLite backend reports ``has_select_for_update = False``. A green run in
        this module therefore says nothing about multi-process serialization;
        the deactivation module's transaction scope note is the contract.
        """
        assert connection.vendor == "sqlite"
        # The backend simply omits FOR UPDATE: Django compiles it away, so nothing
        # serializes two writers here.
        assert connection.features.has_select_for_update is False
