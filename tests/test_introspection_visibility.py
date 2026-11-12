"""Tests for caller-specific introspection visibility (RFC 7662 section 2.2)."""

import calendar
import datetime
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.authorization_server.introspection_visibility import (
    ACTIVE_ONLY,
    EVERYTHING,
    HIDDEN,
    VISIBLE_FIELDS,
    AllFieldsPolicy,
    CallerResourcePolicy,
    IntrospectionContext,
    IntrospectionVisibility,
    IntrospectionVisibilityPolicy,
    evaluate_visibility,
)
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.settings import oauth2_settings

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
RESOURCE_A = "https://a.example.com"
RESOURCE_B = "https://b.example.com"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.INTROSPECTION_RESTRICTED_SETTINGS)
class TestIntrospectionVisibilityEndToEnd(TestCase):
    """Two trusted resource-server clients share one introspection endpoint.

    Service A queries a user token issued to service B. A learns that the token is
    active (it needs that to decide whether to use it) but none of its details;
    B, the token's own application, reads the full response.
    """

    @classmethod
    def setUpTestData(cls):
        cls.resource_owner = UserModel.objects.create_user("resource_owner")
        cls.other_owner = UserModel.objects.create_user("other_owner")

        cls.service_a = Application.objects.create(
            name="Service A",
            user=cls.resource_owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.service_b = Application.objects.create(
            name="Service B",
            user=cls.other_owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        expires = timezone.now() + datetime.timedelta(days=1)
        # Each service introspects with an access token of its own. They are not
        # resource-bound: an RFC 8707 audience would have to name the introspection
        # endpoint, not the service's own API. Both are trusted: can_introspect is
        # the model default and their tokens carry the introspection scope.
        cls.caller_token_a = AccessToken.objects.create(
            user=cls.resource_owner,
            application=cls.service_a,
            token="caller-token-a",
            expires=expires,
            scope="introspection",
        )
        cls.caller_token_b = AccessToken.objects.create(
            user=cls.other_owner,
            application=cls.service_b,
            token="caller-token-b",
            expires=expires,
            scope="introspection",
        )
        # The user's token was issued for service B; service A only shares the endpoint.
        cls.cross_resource_token = AccessToken.objects.create(
            user=cls.other_owner,
            application=cls.service_b,
            token="cross-resource-token",
            expires=expires,
            scope="read write",
            resource=[RESOURCE_B],
        )
        cls.b_token = AccessToken.objects.create(
            user=cls.other_owner,
            application=cls.service_b,
            token="b-token",
            expires=expires,
            scope="read",
            resource=[RESOURCE_B],
        )
        cls.expired_cross_resource_token = AccessToken.objects.create(
            user=cls.other_owner,
            application=cls.service_b,
            token="expired-cross-resource-token",
            expires=timezone.now() - datetime.timedelta(seconds=1),
            scope="read write",
            resource=[RESOURCE_B],
        )
        cls.unrestricted_token = AccessToken.objects.create(
            user=cls.other_owner,
            application=cls.service_b,
            token="unrestricted-token",
            expires=expires,
            scope="read",
        )

    def _introspect(self, token, caller_token):
        return post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": token.token},
            HTTP_AUTHORIZATION="Bearer " + caller_token.token,
        )

    def test_token_application_reads_all_fields(self):
        response = self._introspect(self.cross_resource_token, self.caller_token_b)
        assert response.status_code == 200
        assert response.json() == {
            "active": True,
            "scope": "read write",
            "client_id": self.service_b.client_id,
            "username": self.other_owner.get_username(),
            "exp": int(calendar.timegm(self.cross_resource_token.expires.timetuple())),
            "aud": [RESOURCE_B],
        }

    def test_other_caller_learns_active_but_no_fields(self):
        response = self._introspect(self.cross_resource_token, self.caller_token_a)
        assert response.status_code == 200
        assert response.json() == {"active": True}

    def test_other_caller_does_not_learn_the_tokens_details(self):
        response = self._introspect(self.cross_resource_token, self.caller_token_a)
        body = response.json()
        for field in ("username", "scope", "aud", "client_id", "exp"):
            assert field not in body

    def test_inactive_token_is_bare_inactive_for_every_caller(self):
        for caller_token in (self.caller_token_a, self.caller_token_b):
            response = self._introspect(self.expired_cross_resource_token, caller_token)
            assert response.status_code == 200
            assert response.json() == {"active": False}

    def test_token_without_user_and_application_is_projected_safely(self):
        token = AccessToken.objects.create(
            user=None,
            application=None,
            token="orphan-token",
            expires=timezone.now() + datetime.timedelta(days=1),
            scope="read",
            resource=[RESOURCE_B],
        )
        response = self._introspect(token, self.caller_token_b)
        assert response.status_code == 200
        # The token has no application, so no caller is its application: active only.
        assert response.json() == {"active": True}

    def test_client_authentication_path_uses_the_authenticated_caller(self):
        # Service A authenticates as itself: the token was issued to service B, so
        # A learns active only.
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.cross_resource_token.token},
            **get_basic_auth_header(self.service_a.client_id, CLEARTEXT_SECRET),
        )
        assert response.status_code == 200
        assert response.json() == {"active": True}

        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.b_token.token},
            **get_basic_auth_header(self.service_b.client_id, CLEARTEXT_SECRET),
        )
        assert response.status_code == 200
        # The token was issued to service B: its own application reads everything.
        assert response.json()["username"] == self.other_owner.get_username()

    def test_restrictive_policy_also_hides_an_unbound_token_from_other_callers(self):
        response = self._introspect(self.unrestricted_token, self.caller_token_a)
        assert response.status_code == 200
        assert response.json() == {"active": True}

    def test_unauthenticated_caller_is_still_refused(self):
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.cross_resource_token.token},
            HTTP_AUTHORIZATION="Bearer not-a-token",
        )
        assert response.status_code == 403
        assert response.content == b""

    def test_can_introspect_off_still_refuses_before_projection(self):
        Application.objects.filter(pk=self.service_a.pk).update(can_introspect=False)
        response = self._introspect(self.cross_resource_token, self.caller_token_a)
        assert response.status_code == 403
        assert response.content == b""


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.INTROSPECTION_RESTRICTED_SETTINGS)
class TestIntrospectionVisibilityPolicyErrors(TestCase):
    """A policy that cannot decide discloses nothing; it never falls back to all."""

    @classmethod
    def setUpTestData(cls):
        cls.owner = UserModel.objects.create_user("policy_owner")
        cls.caller = Application.objects.create(
            name="Caller",
            user=cls.owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.target = Application.objects.create(
            name="Target",
            user=cls.owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        expires = timezone.now() + datetime.timedelta(days=1)
        cls.caller_token = AccessToken.objects.create(
            user=cls.owner,
            application=cls.caller,
            token="policy-caller-token",
            expires=expires,
            scope="introspection",
        )
        cls.target_token = AccessToken.objects.create(
            user=cls.owner,
            application=cls.target,
            token="policy-target-token",
            expires=expires,
            scope="read",
            resource=[RESOURCE_B],
        )

    def setUp(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = (
            "oauth2_provider.authorization_server.introspection_visibility.IntrospectionVisibilityPolicy"
        )

    def _introspect(self):
        return post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.target_token.token},
            HTTP_AUTHORIZATION="Bearer " + self.caller_token.token,
        )

    def _assert_hidden(self, response):
        assert response.status_code == 200
        assert response.content == b'{"active": false}'

    def test_policy_exception_is_hidden_and_logged(self):
        def explode(context):
            raise RuntimeError("policy failure")

        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = explode
        with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
            response = self._introspect()

        self._assert_hidden(response)
        assert any("RuntimeError" in record.getMessage() for record in logs.records)

    def test_unresolvable_policy_setting_is_hidden_not_a_500(self):
        # A dotted path that no longer resolves is a deployment error. It must not
        # become a 500 that also reveals the token exists. Configure it the way a
        # deployment does (OAUTH2_PROVIDER), so the import-string resolution runs.
        settings_dict = dict(presets.INTROSPECTION_RESTRICTED_SETTINGS)
        settings_dict["INTROSPECTION_VISIBILITY_POLICY"] = "no.such.module.NoSuchPolicy"
        with override_settings(OAUTH2_PROVIDER=settings_dict):
            oauth2_settings.reload()
            with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
                response = self._introspect()

        self._assert_hidden(response)
        assert any("ImportError" in record.getMessage() for record in logs.records)

    def test_policy_returning_none_is_hidden(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: None
        self._assert_hidden(self._introspect())

    def test_policy_returning_a_bare_string_is_hidden(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: "username"
        self._assert_hidden(self._introspect())

    def test_get_visibility_returning_a_bad_type_is_hidden(self):
        class Broken:
            @staticmethod
            def get_visibility(context):
                return "everything"

        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = Broken
        self._assert_hidden(self._introspect())

    def test_policy_error_does_not_leak_the_token(self):
        def explode(context):
            raise RuntimeError("failure mentioning " + context.token.token)

        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = explode
        with self.assertLogs("oauth2_provider.authorization_server.views.introspect", "WARNING") as logs:
            response = self._introspect()

        self._assert_hidden(response)
        assert self.target_token.token not in "\n".join(record.getMessage() for record in logs.records)

    def test_mapping_return_form_controls_both_decisions(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: {
            "active": True,
            "username": True,
            "scope": False,
        }
        response = self._introspect()
        assert response.status_code == 200
        assert response.json() == {"active": True, "username": self.owner.get_username()}

    def test_mapping_return_form_can_deny_active(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: {
            "active": False,
            "username": True,
        }
        self._assert_hidden(self._introspect())

    def test_bool_pair_return_form(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: (True, {"exp"})
        response = self._introspect()
        assert response.status_code == 200
        assert set(response.json()) == {"active", "exp"}

    def test_unknown_field_names_are_ignored(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: [
            "username",
            "token",
            "error",
            "active",
            "not_a_field",
        ]
        response = self._introspect()
        assert response.status_code == 200
        body = response.json()
        assert body["active"] is True
        assert body["username"] == self.owner.get_username()
        for field in ("token", "error", "not_a_field"):
            assert field not in body

    def test_active_denial_hides_the_token(self):
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = lambda context: HIDDEN
        self._assert_hidden(self._introspect())

    def test_authentication_checks_run_before_the_policy(self):
        calls = []

        def policy(context):
            calls.append(context)
            return VISIBLE_FIELDS

        Application.objects.filter(pk=self.caller.pk).update(can_introspect=False)
        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = policy
        response = self._introspect()

        assert response.status_code == 403
        assert calls == []

    def test_policy_cannot_authorize_an_unauthenticated_request(self):
        calls = []

        def policy(context):
            calls.append(context)
            return VISIBLE_FIELDS

        self.oauth2_settings.INTROSPECTION_VISIBILITY_POLICY = policy
        response = post_form(
            self.client,
            reverse("oauth2_provider:introspect"),
            {"token": self.target_token.token},
        )

        assert response.status_code == 403
        assert calls == []


class TestIntrospectionDefaultPolicy(TestCase):
    """The default setting keeps the pre-policy response for existing deployments."""

    @classmethod
    def setUpTestData(cls):
        cls.owner = UserModel.objects.create_user("default_owner")
        cls.caller = Application.objects.create(
            name="Default caller",
            user=cls.owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        cls.issuer = Application.objects.create(
            name="Token issuer",
            user=cls.owner,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
        )
        expires = timezone.now() + datetime.timedelta(days=1)
        cls.caller_token = AccessToken.objects.create(
            user=cls.owner,
            application=cls.caller,
            token="default-caller-token",
            expires=expires,
            scope="introspection",
        )
        cls.target_token = AccessToken.objects.create(
            user=cls.owner,
            application=cls.issuer,
            token="default-target-token",
            expires=expires,
            scope="read",
            resource=[RESOURCE_B],
        )

    def test_unconfigured_policy_keeps_the_full_response(self):
        # OAUTH2_PROVIDER without the key: an ordinary deployment upgrading to this
        # version must see the response it saw before.
        with override_settings(OAUTH2_PROVIDER=dict(presets.INTROSPECTION_VISIBILITY_SETTINGS)):
            oauth2_settings.reload()
            response = post_form(
                self.client,
                reverse("oauth2_provider:introspect"),
                {"token": self.target_token.token},
                HTTP_AUTHORIZATION="Bearer " + self.caller_token.token,
            )

        assert response.status_code == 200
        assert response.json() == {
            "active": True,
            "scope": "read",
            "client_id": self.issuer.client_id,
            "username": self.owner.get_username(),
            "exp": int(calendar.timegm(self.target_token.expires.timetuple())),
            "aud": [RESOURCE_B],
        }


class TestVisibilityPolicyUnits:
    """Direct tests for the policy protocol and its normalization."""

    @staticmethod
    def _context(
        allows=lambda uri: False,
        resource=(RESOURCE_B,),
        caller_id="caller",
        application=None,
        caller_pk=1,
    ):
        caller = SimpleNamespace(client_id=caller_id, pk=caller_pk)
        token = SimpleNamespace(
            resource=list(resource),
            application=application,
            user=None,
            allows_audience=allows,
        )
        return IntrospectionContext(caller=caller, token=token)

    def test_default_policy_hides_details_from_unrelated_callers(self):
        assert IntrospectionVisibilityPolicy.get_visibility(self._context()) == ACTIVE_ONLY

    def test_all_fields_policy_is_everything(self):
        assert AllFieldsPolicy.get_visibility(self._context()) == EVERYTHING

    def test_caller_resource_policy_matches_declared_resource(self):
        policy = CallerResourcePolicy(resources={"service-a": [RESOURCE_A]})
        context = self._context(
            allows=lambda uri: uri == RESOURCE_A,
            resource=[RESOURCE_A],
            caller_id="service-a",
        )
        assert policy.get_visible_fields(context) == VISIBLE_FIELDS
        assert policy.can_see_active(context) is True

    def test_caller_resource_policy_no_match_hides_fields(self):
        policy = CallerResourcePolicy(resources={"service-a": [RESOURCE_A]})
        context = self._context(
            allows=lambda uri: uri == RESOURCE_B,
            resource=[RESOURCE_B],
            caller_id="service-a",
        )
        assert policy.get_visible_fields(context) == frozenset()

    def test_caller_resource_policy_can_deny_active(self):
        policy = CallerResourcePolicy(resources={"service-a": [RESOURCE_A]})
        policy.deny_active = frozenset({"service-a"})
        context = self._context(allows=lambda uri: True, caller_id="service-a")
        assert policy.can_see_active(context) is False
        assert policy.get_visible_fields(context) == frozenset()

    def test_evaluate_normalizes_a_field_iterable(self):
        visibility, error = evaluate_visibility(lambda context: {"username", "bogus"}, self._context())
        assert error is None
        assert visibility == IntrospectionVisibility(allow_active=True, fields=frozenset({"username"}))

    def test_evaluate_hides_on_error(self):
        def explode(context):
            raise ValueError("nope")

        visibility, error = evaluate_visibility(explode, self._context())
        assert visibility == HIDDEN
        assert isinstance(error, ValueError)

    def test_evaluate_prefers_get_visibility(self):
        class Policy:
            @staticmethod
            def get_visibility(context):
                return HIDDEN

            @staticmethod
            def get_visible_fields(context):
                return VISIBLE_FIELDS

        visibility, error = evaluate_visibility(Policy, self._context())
        assert error is None
        assert visibility == HIDDEN

    def test_evaluate_combines_can_see_active_with_fields(self):
        class Policy:
            @staticmethod
            def can_see_active(context):
                return False

            @staticmethod
            def get_visible_fields(context):
                return VISIBLE_FIELDS

        visibility, error = evaluate_visibility(Policy, self._context())
        assert error is None
        assert visibility.allow_active is False
        assert visibility.fields == VISIBLE_FIELDS
