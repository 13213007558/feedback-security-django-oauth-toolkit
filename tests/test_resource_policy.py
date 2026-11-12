"""RFC 8707 resource-policy versioning: matching rules, issuance, refresh, audit."""

import datetime
import json

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.core.resource_policy import (
    RESOURCE_POLICY_EXACT,
    RESOURCE_POLICY_LEGACY,
    RESOURCE_POLICY_PREFIX,
)
from oauth2_provider.management.commands.resourcepolicy import (
    OUTCOME_INVALID,
    OUTCOME_MIGRATABLE,
    OUTCOME_OVERLAP,
    OUTCOME_UNRESTRICTED,
    classify_resources,
)
from oauth2_provider.models import AccessToken, Grant, RefreshToken, get_application_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.resource_server.validators import (
    resource_identifiers_equal,
    validate_resource_as_exact_uri,
    validate_resource_for_policy,
)

from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import post_form


@pytest.fixture
def allow_testserver():
    """Django's test client sends Host: testserver, which tests/settings.py does not allow."""
    host = settings.ALLOWED_HOSTS
    settings.ALLOWED_HOSTS = [*host, "testserver", "localhost"]
    yield
    settings.ALLOWED_HOSTS = host


EXACT = {"RESOURCE_POLICY": RESOURCE_POLICY_EXACT, "PKCE_REQUIRED": False, "SCOPES": {"read": "Read"}}


class TestExactMatching:
    """The version 2 matcher: identity, not prefix."""

    def test_exact_identifier_matches(self):
        assert validate_resource_as_exact_uri("https://api.example.com/v1", ["https://api.example.com/v1"])

    def test_sub_path_does_not_match(self):
        """A token for /v1 is not a token for /v1/users."""
        assert not validate_resource_as_exact_uri(
            "https://api.example.com/v1/users", ["https://api.example.com/v1"]
        )

    def test_longer_path_does_not_match(self):
        assert not validate_resource_as_exact_uri(
            "https://api.example.com/v1", ["https://api.example.com/v1/users"]
        )

    def test_address_format_differences_are_equal(self):
        for request_uri in (
            "https://API.Example.com/v1",
            "HTTPS://api.example.com/v1",
            "https://api.example.com:443/v1",
            "https://api.example.com/v1/",
            "https://api.example.com/x/../v1",
            "https://api.example.com/v1?tenant=1",
        ):
            assert validate_resource_as_exact_uri(request_uri, ["https://api.example.com/v1"]), request_uri

    def test_query_is_not_part_of_the_identifier(self):
        assert validate_resource_as_exact_uri(
            "https://api.example.com/v1?a=1", ["https://api.example.com/v1?b=2"]
        )

    def test_path_case_is_part_of_the_identifier(self):
        """Paths are case-sensitive in URIs, so a path spelling difference is a permission difference."""
        assert not validate_resource_as_exact_uri(
            "https://api.example.com/V1", ["https://api.example.com/v1"]
        )

    def test_unrestricted_allows_anything(self):
        assert validate_resource_as_exact_uri("https://any.example.com/x", [])

    def test_prefix_and_exact_disagree_on_sub_paths(self):
        """The demonstration that distinguishes an address-format change from a permission change."""
        resource = "https://api.example.com/v1"
        assert validate_resource_for_policy(
            "https://api.example.com/v1/users", [resource], RESOURCE_POLICY_PREFIX
        )
        assert not validate_resource_for_policy(
            "https://api.example.com/v1/users", [resource], RESOURCE_POLICY_EXACT
        )
        # Just a spelling difference: permitted under both.
        spelling = "https://api.example.com:443/v1/"
        assert validate_resource_for_policy(spelling, [resource], RESOURCE_POLICY_PREFIX)
        assert validate_resource_for_policy(spelling, [resource], RESOURCE_POLICY_EXACT)

    def test_blank_policy_is_legacy_prefix(self):
        assert validate_resource_for_policy(
            "https://api.example.com/v1/users", ["https://api.example.com/v1"], RESOURCE_POLICY_LEGACY
        )

    def test_exact_cannot_be_relaxed_by_custom_validator(self, settings):
        """A permissive RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR must not re-open exact tokens."""
        settings.OAUTH2_PROVIDER = {
            "RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR": "tests.test_resource_policy.allow_all"
        }
        assert not validate_resource_for_policy(
            "https://api.example.com/v1/users", ["https://api.example.com/v1"], RESOURCE_POLICY_EXACT
        )

    def test_resource_identifiers_equal(self):
        assert resource_identifiers_equal("https://A.example.com:443/x/../y", "https://a.example.com/y")
        assert not resource_identifiers_equal("https://api.example.com/v1", "https://api.example.com/v2")


def allow_all(request_uri, audiences):
    return True


@pytest.mark.usefixtures("oauth2_settings")
class TestPolicyBoundTokens(TestCase):
    """A token answers with the rule recorded on it, not the current setting."""

    def _token(self, policy, resource):
        user = get_user_model().objects.create_user("policy_user", "p@example.com", "123456")
        app = get_application_model().objects.create(
            name="Policy App",
            client_type="public",
            authorization_grant_type="authorization-code",
            user=user,
        )
        return AccessToken.objects.create(
            user=user,
            application=app,
            token=f"token-{policy or 'legacy'}",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=resource,
            resource_policy=policy,
        )

    def test_legacy_token_keeps_prefix_after_switch(self):
        self.oauth2_settings.RESOURCE_POLICY = RESOURCE_POLICY_EXACT
        token = self._token(RESOURCE_POLICY_LEGACY, ["https://api.example.com/v1"])
        assert token.allows_audience("https://api.example.com/v1/users")

    def test_exact_token_stays_exact_after_rollback(self):
        self.oauth2_settings.RESOURCE_POLICY = RESOURCE_POLICY_PREFIX
        token = self._token(RESOURCE_POLICY_EXACT, ["https://api.example.com/v1"])
        assert not token.allows_audience("https://api.example.com/v1/users")
        assert token.allows_audience("https://api.example.com/v1")


@pytest.mark.django_db(databases="__all__")
@pytest.mark.usefixtures("allow_testserver")
class TestIssuanceRecordsPolicy:
    def _application(self):
        user = get_user_model().objects.create_user("issuer", "i@example.com", "123456")
        return user, get_application_model().objects.create(
            name="Issuer",
            user=user,
            client_type="confidential",
            authorization_grant_type="authorization-code",
            redirect_uris="https://client.example.com/callback",
            skip_authorization=True,
            client_secret="plaintext-secret",
        )

    def test_exact_issuance_records_exact_everywhere(self, client, oauth2_settings):
        oauth2_settings.update(EXACT)
        user, app = self._application()
        client.force_login(user)
        auth_url = reverse("oauth2_provider:authorize")
        response = client.get(
            f"{auth_url}?client_id={app.client_id}&response_type=code"
            "&redirect_uri=https://client.example.com/callback&scope=read"
            "&resource=https://api.example.com/v1"
        )
        assert response.status_code == 302
        code = response["Location"].split("code=")[1].split("&")[0]
        grant = Grant.objects.get(code=code)
        assert grant.resource_policy == RESOURCE_POLICY_EXACT

        token_response = post_form(
            client,
            reverse("oauth2_provider:token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://client.example.com/callback",
                "client_id": app.client_id,
                "client_secret": "plaintext-secret",
            },
        )
        assert token_response.status_code == 200
        token = AccessToken.objects.get(token=token_response.json()["access_token"])
        refresh = RefreshToken.objects.get(token=token_response.json()["refresh_token"])
        assert token.resource_policy == RESOURCE_POLICY_EXACT
        assert refresh.resource_policy == RESOURCE_POLICY_EXACT

    def test_prefix_issuance_keeps_prefix(self, client, oauth2_settings):
        oauth2_settings.update({"PKCE_REQUIRED": False})
        user, app = self._application()
        client.force_login(user)
        auth_url = reverse("oauth2_provider:authorize")
        response = client.get(
            f"{auth_url}?client_id={app.client_id}&response_type=code"
            "&redirect_uri=https://client.example.com/callback&scope=read"
            "&resource=https://api.example.com/v1"
        )
        code = response["Location"].split("code=")[1].split("&")[0]
        assert Grant.objects.get(code=code).resource_policy == RESOURCE_POLICY_PREFIX

    def test_exact_refuses_query_in_resource(self, client, oauth2_settings):
        oauth2_settings.update(EXACT)
        user, app = self._application()
        app.authorization_grant_type = app.GRANT_CLIENT_CREDENTIALS
        app.save()
        assert self.oauth2_settings.RESOURCE_POLICY == "exact"
        token_response = post_form(
            client,
            reverse("oauth2_provider:token"),
            {
                "grant_type": "client_credentials",
                "client_id": app.client_id,
                "client_secret": "plaintext-secret",
                "resource": "https://api.example.com/v1?tenant=1",
            },
        )
        assert token_response.status_code == 400
        assert json.loads(token_response.content)["error"] == "invalid_target"

    def test_unknown_policy_is_an_error(self, oauth2_settings):
        oauth2_settings.RESOURCE_POLICY = "wildcard"
        with pytest.raises(ImproperlyConfigured):
            OAuth2Validator().get_resource_policy()


@pytest.mark.django_db(databases="__all__")
@pytest.mark.usefixtures("allow_testserver")
class TestRefreshTransition:
    def _legacy_pair(self, resources):
        user = get_user_model().objects.create_user("legacy", "l@example.com", "123456")
        app = get_application_model().objects.create(
            name="Legacy",
            user=user,
            client_type="confidential",
            authorization_grant_type="authorization-code",
            redirect_uris="https://client.example.com/callback",
            client_secret="secret",
        )
        token = AccessToken.objects.create(
            user=user,
            application=app,
            token="legacy-access",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=resources,
        )
        refresh = RefreshToken.objects.create(
            user=user,
            application=app,
            access_token=token,
            token="legacy-refresh",
            resource=resources,
        )
        return user, app, refresh

    def _refresh(self, client, app, refresh, **extra):
        return post_form(
            client,
            reverse("oauth2_provider:token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh.token,
                "client_id": app.client_id,
                "client_secret": "secret",
                **extra,
            },
        )

    def test_legacy_unrestricted_refresh_cannot_continue_unrestricted(self, client, oauth2_settings):
        """The key restriction: a pre-switch unrestricted refresh cannot stay unrestricted."""
        oauth2_settings.update(EXACT)
        user, app, refresh = self._legacy_pair([])
        response = self._refresh(client, app, refresh)
        assert response.status_code == 400
        content = json.loads(response.content)
        assert content["error"] == "invalid_target"
        assert "no resource restriction" in content["error_description"]

    def test_legacy_unrestricted_refresh_with_named_resource_moves_to_exact(self, client, oauth2_settings):
        oauth2_settings.update(EXACT)
        user, app, refresh = self._legacy_pair([])
        response = self._refresh(client, app, refresh, resource="https://api.example.com/v1")
        assert response.status_code == 200
        token = AccessToken.objects.get(token=response.json()["access_token"])
        assert token.resource == ["https://api.example.com/v1"]
        assert token.resource_policy == RESOURCE_POLICY_EXACT

    def test_legacy_restricted_refresh_stays_prefix(self, client, oauth2_settings):
        """A pre-switch prefix grant does not silently become exact on refresh."""
        oauth2_settings.update(EXACT)
        user, app, refresh = self._legacy_pair(["https://api.example.com/v1"])
        response = self._refresh(client, app, refresh)
        assert response.status_code == 200
        token = AccessToken.objects.get(token=response.json()["access_token"])
        assert token.resource_policy == RESOURCE_POLICY_PREFIX
        assert token.allows_audience("https://api.example.com/v1/users")

    def test_exact_refresh_cannot_widen_on_rollback(self, client, oauth2_settings):
        oauth2_settings.update({"PKCE_REQUIRED": False})
        user, app, refresh = self._legacy_pair(["https://api.example.com/v1"])
        refresh.resource_policy = RESOURCE_POLICY_EXACT
        refresh.access_token.resource_policy = RESOURCE_POLICY_EXACT
        refresh.save()
        refresh.access_token.save()
        response = self._refresh(client, app, refresh)
        assert response.status_code == 200
        token = AccessToken.objects.get(token=response.json()["access_token"])
        assert token.resource_policy == RESOURCE_POLICY_EXACT

    def test_refresh_accepts_equivalent_spelling_under_exact(self, client, oauth2_settings):
        oauth2_settings.update(EXACT)
        user, app, refresh = self._legacy_pair(["https://api.example.com/v1"])
        refresh.resource_policy = RESOURCE_POLICY_EXACT
        refresh.access_token.resource_policy = RESOURCE_POLICY_EXACT
        refresh.save()
        refresh.access_token.save()
        response = self._refresh(client, app, refresh, resource="https://API.example.com:443/v1/")
        assert response.status_code == 200


@pytest.mark.django_db(databases="__all__")
class TestIntrospectionPolicy:
    def _setup(self):
        user = get_user_model().objects.create_user("introspect", "s@example.com", "123456")
        app = get_application_model().objects.create(
            name="Introspector",
            user=user,
            client_type="confidential",
            authorization_grant_type="client-credentials",
            client_secret="secret",
        )
        rs_token = AccessToken.objects.create(
            user=user,
            application=app,
            token="introspection-token",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="introspection",
        )
        return app, rs_token

    def test_introspection_reports_policy(self, client, oauth2_settings):
        app, rs_token = self._setup()
        AccessToken.objects.create(
            user=rs_token.user,
            application=app,
            token="bonded",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=["https://api.example.com/v1"],
            resource_policy=RESOURCE_POLICY_EXACT,
        )
        response = post_form(
            client,
            reverse("oauth2_provider:introspect"),
            {"token": "bonded"},
            HTTP_AUTHORIZATION="Bearer " + rs_token.token,
        )
        assert response.status_code == 200
        content = response.json()
        assert content["aud"] == ["https://api.example.com/v1"]
        assert content["resource_policy"] == RESOURCE_POLICY_EXACT

    def test_introspection_reports_prefix_for_legacy(self, client):
        app, rs_token = self._setup()
        AccessToken.objects.create(
            user=rs_token.user,
            application=app,
            token="bonded-legacy",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=["https://api.example.com/v1"],
        )
        response = post_form(
            client,
            reverse("oauth2_provider:introspect"),
            {"token": "bonded-legacy"},
            HTTP_AUTHORIZATION="Bearer " + rs_token.token,
        )
        assert response.json()["resource_policy"] == RESOURCE_POLICY_PREFIX


class TestClassifyResources:
    def test_empty_is_unrestricted(self):
        assert classify_resources([])[0] == OUTCOME_UNRESTRICTED

    def test_single_resource_is_migratable(self):
        assert classify_resources(["https://api.example.com/v1"])[0] == OUTCOME_MIGRATABLE

    def test_distinct_hosts_are_migratable(self):
        assert (
            classify_resources(["https://a.example.com/v1", "https://b.example.com/v1"])[0]
            == OUTCOME_MIGRATABLE
        )

    def test_overlapping_prefixes_are_not_migratable(self):
        first = "https://api.example.com/v1"
        second = "https://api.example.com/v1/users"
        assert classify_resources([first, second])[0] == OUTCOME_OVERLAP

    def test_invalid_resource_is_flagged(self):
        assert classify_resources(["/not/absolute"])[0] == OUTCOME_INVALID

    def test_trailing_slash_spelling_is_overlap(self):
        assert (
            classify_resources(["https://api.example.com/v1", "https://api.example.com/v1/"])[0]
            == OUTCOME_OVERLAP
        )


@pytest.mark.django_db(databases="__all__")
class TestResourcePolicyCommand:
    def _rows(self):
        user = get_user_model().objects.create_user("cmd", "c@example.com", "123456")
        app = get_application_model().objects.create(
            name="Cmd",
            user=user,
            client_type="public",
            authorization_grant_type="authorization-code",
        )
        migratable = AccessToken.objects.create(
            user=user,
            application=app,
            token="migratable",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=["https://api.example.com/v1"],
        )
        overlapping = AccessToken.objects.create(
            user=user,
            application=app,
            token="overlapping",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=["https://api.example.com/v1", "https://api.example.com/v1/users"],
        )
        unrestricted = AccessToken.objects.create(
            user=user,
            application=app,
            token="unrestricted",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
            resource=[],
        )
        return migratable, overlapping, unrestricted

    def test_audit_reports_but_does_not_write(self, capsys):
        rows = self._rows()
        call_command("resourcepolicy", "--audit")
        output = capsys.readouterr().out
        assert "migratable" in output
        assert "overlapping prefixes" in output
        assert "unrestricted" in output
        for row in rows:
            row.refresh_from_db()
            assert row.resource_policy == ""

    def test_migrate_moves_only_safe_rows(self, capsys):
        migratable, overlapping, unrestricted = self._rows()
        call_command("resourcepolicy", "--migrate")
        migratable.refresh_from_db()
        overlapping.refresh_from_db()
        unrestricted.refresh_from_db()
        assert migratable.resource_policy == RESOURCE_POLICY_EXACT
        assert overlapping.resource_policy == ""
        assert unrestricted.resource_policy == ""

    def test_purge_unsafe_removes_flagged_rows(self, capsys):
        migratable, overlapping, unrestricted = self._rows()
        call_command("resourcepolicy", "--migrate", "--purge-unsafe")
        assert not AccessToken.objects.filter(pk=overlapping.pk).exists()
        assert not AccessToken.objects.filter(pk=unrestricted.pk).exists()
        assert AccessToken.objects.filter(pk=migratable.pk).exists()

    def test_unknown_target_policy_is_refused(self, capsys):
        call_command("resourcepolicy", "--migrate", "--policy", "prefix")
        assert "only accepts 'exact'" in capsys.readouterr().err

    def test_audit_wins_over_migrate(self):
        migratable, _overlapping, _unrestricted = self._rows()
        call_command("resourcepolicy", "--migrate", "--audit")
        migratable.refresh_from_db()
        assert migratable.resource_policy == ""


@pytest.mark.django_db(databases="__all__")
@pytest.mark.usefixtures("allow_testserver")
class TestTransitionDemonstration:
    """The before/after picture for two path-bearing resources and a historic unrestricted record."""

    TENANT_A = "https://api.example.com/tenants/acme"
    TENANT_B = "https://api.example.com/tenants/beta"

    def _app(self):
        user = get_user_model().objects.create_user("demo", "d@example.com", "123456")
        app = get_application_model().objects.create(
            name="Demo",
            user=user,
            client_type="confidential",
            authorization_grant_type="client-credentials",
            client_secret="secret",
        )
        return app

    def _issue(self, client, app, resource):
        response = post_form(
            client,
            reverse("oauth2_provider:token"),
            {
                "grant_type": "client_credentials",
                "client_id": app.client_id,
                "client_secret": "secret",
                "resource": resource,
            },
        )
        assert response.status_code == 200
        return AccessToken.objects.get(token=response.json()["access_token"])

    def test_before_and_after(self, client, oauth2_settings):
        app = self._app()

        # Before the switch: two tokens, one per path-bearing resource.
        oauth2_settings.update({"PKCE_REQUIRED": False})
        token_a = self._issue(client, app, self.TENANT_A)
        token_b = self._issue(client, app, self.TENANT_B)
        assert token_a.resource_policy == RESOURCE_POLICY_PREFIX
        assert token_b.resource_policy == RESOURCE_POLICY_PREFIX

        # Prefix matching: each token reaches its own tenant's sub-paths...
        assert token_a.allows_audience(f"{self.TENANT_A}/documents")
        assert token_b.allows_audience(f"{self.TENANT_B}/documents")
        # ...but neither reaches the sibling tenant, which shares only a path prefix up
        # to /tenants/, not a whole path-segment prefix.
        assert not token_a.allows_audience(self.TENANT_B)
        assert not token_b.allows_audience(self.TENANT_A)
        # A spelling difference is the same address, so it matches under both policies.
        assert token_a.allows_audience("https://API.example.com:443/tenants/acme")

        # After the switch the same two requests issue exact-policy tokens.
        oauth2_settings.update(EXACT)
        exact_a = self._issue(client, app, self.TENANT_A)
        exact_b = self._issue(client, app, self.TENANT_B)
        assert exact_a.resource_policy == RESOURCE_POLICY_EXACT
        assert exact_b.resource_policy == RESOURCE_POLICY_EXACT

        # Each exact token matches its own identifier, including a spelling difference.
        assert exact_a.allows_audience(self.TENANT_A)
        assert exact_a.allows_audience("https://API.example.com:443/tenants/acme/")
        assert exact_b.allows_audience(self.TENANT_B)
        # But a sub-path is now a different resource: the permission shrank, and the
        # sibling tenant was never authorized.
        assert not exact_a.allows_audience(f"{self.TENANT_A}/documents")
        assert not exact_b.allows_audience(f"{self.TENANT_B}/documents")
        assert not exact_a.allows_audience(self.TENANT_B)

        # The pre-switch tokens are not reinterpreted by the switch.
        assert token_a.allows_audience(f"{self.TENANT_A}/documents")
        assert token_a.resource_policy == RESOURCE_POLICY_PREFIX

        # A historic record with no resource restriction was never audience-checked; under
        # either policy it is accepted everywhere, which is why the audit flags it as
        # impossible to narrow instead of migrating it.
        historic = AccessToken.objects.create(
            user=get_user_model().objects.create_user("historic", "h@example.com", "123456"),
            application=app,
            token="historic-unrestricted",
            expires=timezone.now() + datetime.timedelta(hours=1),
            scope="read",
        )
        assert historic.resource_policy == RESOURCE_POLICY_LEGACY
        assert historic.allows_audience(self.TENANT_A)
        assert historic.allows_audience(self.TENANT_B)
        assert classify_resources(historic.resource)[0] == OUTCOME_UNRESTRICTED
