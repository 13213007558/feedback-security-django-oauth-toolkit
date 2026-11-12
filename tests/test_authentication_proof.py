"""Scope gating on proof of (recent, strengthened) authentication.

The authentication system records an :class:`AuthenticationProof` (the default
backend keeps it in the Django session); the authorization server checks it
against ``SCOPE_AUTHENTICATION_REQUIREMENTS`` at the authorization endpoint,
at authorization-code exchange and on every refresh. Client-sent request
parameters are never proof. The clock is controlled throughout with
``authentication_clock``.
"""

import json
from datetime import datetime
from datetime import timezone as datetime_timezone
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.authorization_server import authentication
from oauth2_provider.authorization_server.authentication import (
    AUTHENTICATION_PROOF_SESSION_KEY,
    AuthenticationProof,
    SessionAuthenticationProofBackend,
    record_authentication_proof,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)

from .utils import get_basic_auth_header, post_form


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
REDIRECT_URI = "http://example.org"
PASSWORD = "123456"

#: The fixed point in time the controllable clock starts at.
T0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=datetime_timezone.utc)

PROOF_SETTINGS = {
    "SCOPES": {
        "read": "Reading scope",
        "write": "Writing scope",
        "payment": "Making payments",
    },
    "DEFAULT_SCOPES": ["read", "write"],
    "PKCE_REQUIRED": False,
    "AUTHENTICATION_PROOF_LEVELS": ["normal", "strong"],
    "SCOPE_AUTHENTICATION_REQUIREMENTS": {
        "payment": {"level": "strong", "max_age_seconds": 300},
    },
}

pytestmark = [
    pytest.mark.django_db(databases="__all__"),
    pytest.mark.usefixtures("oauth2_settings"),
    pytest.mark.oauth2_settings(PROOF_SETTINGS),
]


@pytest.fixture
def clock():
    """The controllable clock: patches authentication_clock, starting at T0."""
    with mock.patch.object(authentication, "authentication_clock", return_value=T0) as patched:
        yield patched


def authorize(client, application, **extra):
    query = {
        "client_id": application.client_id,
        "response_type": "code",
        "state": "random_state_string",
        "scope": "read payment",
        "redirect_uri": REDIRECT_URI,
    }
    query.update(extra)
    return client.get(reverse("oauth2_provider:authorize"), data=query)


def consent(client, application, scope="read payment"):
    data = {
        "client_id": application.client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "state": "random_state_string",
        "scope": scope,
        "allow": True,
    }
    response = client.post(reverse("oauth2_provider:authorize"), data=data)
    assert response.status_code == 302
    query = parse_qs(urlparse(response["Location"]).query)
    assert "code" in query, f"consent did not issue a code: {response['Location']}"
    return query["code"][0]


def exchange_code(client, application, code, **extra):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    data.update(extra)
    auth_headers = get_basic_auth_header(application.client_id, CLEARTEXT_SECRET)
    response = post_form(client, reverse("oauth2_provider:token"), data=data, **auth_headers)
    return response


def refresh(client, application, refresh_token, **extra):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    data.update(extra)
    auth_headers = get_basic_auth_header(application.client_id, CLEARTEXT_SECRET)
    response = post_form(client, reverse("oauth2_provider:token"), data=data, **auth_headers)
    return response


def log_in(client, user):
    assert client.login(username=user.get_username(), password=PASSWORD)


def record_proof(client, level="strong"):
    """What the authentication system does after verifying the end-user."""
    request = RequestFactory().get("/")
    request.session = client.session
    record_authentication_proof(request, level)
    request.session.save()


def login_redirect(response):
    """The ``next`` URL of a redirect to the login page."""
    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert location.path == settings.LOGIN_URL
    return parse_qs(location.query)["next"][0]


def error_redirect(response, error):
    """The query of an error redirected to the client's redirect URI."""
    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert f"{location.scheme}://{location.netloc}" == REDIRECT_URI
    query = parse_qs(location.query)
    assert query["error"] == [error]
    assert query["state"] == ["random_state_string"]
    return query


def issue_token(client, application, scope="read payment"):
    """The whole authorization-code flow; the token response content."""
    code = consent(client, application, scope=scope)
    response = exchange_code(client, application, code)
    assert response.status_code == 200
    return json.loads(response.content.decode("utf-8"))


def test_normal_scopes_keep_their_existing_flow(client, application, test_user, clock):
    """Without a proof, scopes without a requirement flow exactly as before."""
    log_in(client, test_user)

    content = issue_token(client, application, scope="read write")
    assert content["scope"] == "read write"

    response = refresh(client, application, content["refresh_token"])
    assert response.status_code == 200
    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 3600, tz=datetime_timezone.utc)
    content = json.loads(response.content.decode("utf-8"))
    response = refresh(client, application, content["refresh_token"])
    assert response.status_code == 200
    assert json.loads(response.content.decode("utf-8"))["scope"] == "read write"


def test_sensitive_scope_without_proof_sends_the_user_to_reauthenticate(
    client, application, test_user, clock
):
    log_in(client, test_user)

    next_url = login_redirect(authorize(client, application))

    next_query = parse_qs(urlparse(next_url).query)
    assert next_query["scope"] == ["read payment"]
    assert next_query["state"] == ["random_state_string"]


def test_returning_from_reauthentication_without_proof_denies(client, application, test_user, clock):
    """Back from the login page with a fresh login that still proves nothing:
    access_denied, not another redirect (the flow cannot loop)."""
    log_in(client, test_user)
    next_url = login_redirect(authorize(client, application))

    log_in(client, test_user)  # a fresh login, but no strengthened proof
    error_redirect(client.get(next_url), "access_denied")


def test_returning_without_logging_in_again_denies(client, application, test_user, clock):
    log_in(client, test_user)
    next_url = login_redirect(authorize(client, application))

    error_redirect(client.get(next_url), "access_denied")


def test_proof_recorded_by_the_authentication_system_satisfies_the_requirement(
    client, application, test_user, clock
):
    log_in(client, test_user)
    record_proof(client, "strong")

    response = authorize(client, application)
    assert response.status_code == 200  # the consent page, not a login redirect

    content = issue_token(client, application)
    assert content["scope"] == "read payment"

    # The proof travels: grant -> refresh token, with the original time.
    refresh_token = RefreshToken.objects.get(token_checksum__isnull=False)
    assert refresh_token.authentication["level"] == "strong"
    assert refresh_token.authentication["authenticated_at"] == T0.timestamp()


def test_a_weaker_level_does_not_satisfy_the_requirement(client, application, test_user, clock):
    log_in(client, test_user)
    record_proof(client, "normal")

    login_redirect(authorize(client, application))


def test_an_expired_proof_does_not_satisfy_the_requirement(client, application, test_user, clock):
    log_in(client, test_user)
    record_proof(client, "strong")

    # The proof is 301 seconds old; the requirement allows 300.
    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 301, tz=datetime_timezone.utc)
    login_redirect(authorize(client, application))


def test_prompt_none_cannot_reauthenticate_and_gets_interaction_required(
    client, application, test_user, clock
):
    log_in(client, test_user)

    error_redirect(authorize(client, application, prompt="none"), "interaction_required")


def test_proof_expiring_during_consent_denies_the_post(client, application, test_user, clock):
    log_in(client, test_user)
    record_proof(client, "strong")
    assert authorize(client, application).status_code == 200

    # The user sat on the consent page until the proof went stale.
    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 301, tz=datetime_timezone.utc)
    response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "state": "random_state_string",
            "scope": "read payment",
            "allow": True,
        },
    )
    error_redirect(response, "access_denied")
    assert Grant.objects.count() == 0


def test_proof_expired_by_code_exchange_narrows_the_token_scope(client, application, test_user, clock):
    log_in(client, test_user)
    record_proof(client, "strong")
    code = consent(client, application)

    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 301, tz=datetime_timezone.utc)
    response = exchange_code(client, application, code)
    assert response.status_code == 200
    content = json.loads(response.content.decode("utf-8"))
    assert content["scope"] == "read"
    assert AccessToken.objects.get().scope == "read"


def test_refresh_within_the_proof_age_keeps_the_sensitive_scope(client, application, test_user, clock):
    log_in(client, test_user)
    record_proof(client, "strong")
    content = issue_token(client, application)
    assert content["scope"] == "read payment"

    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 299, tz=datetime_timezone.utc)
    response = refresh(client, application, content["refresh_token"])
    assert response.status_code == 200
    assert json.loads(response.content.decode("utf-8"))["scope"] == "read payment"


def test_refresh_after_the_proof_expires_narrows_and_cannot_be_revived(client, application, test_user, clock):
    """Once the proof is stale, a refresh drops the sensitive scope, and no
    refresh of the old credential chain ever brings it back."""
    log_in(client, test_user)
    record_proof(client, "strong")
    content = issue_token(client, application)
    assert content["scope"] == "read payment"

    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 301, tz=datetime_timezone.utc)
    response = refresh(client, application, content["refresh_token"])
    assert response.status_code == 200
    narrowed = json.loads(response.content.decode("utf-8"))
    assert narrowed["scope"] == "read"

    # The rotated refresh token still carries the original proof, so it cannot
    # satisfy the requirement later either.
    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 600, tz=datetime_timezone.utc)
    response = refresh(client, application, narrowed["refresh_token"])
    assert response.status_code == 200
    narrowed = json.loads(response.content.decode("utf-8"))
    assert narrowed["scope"] == "read"

    # Asking for the dropped scope back is out of the narrowed grant.
    response = refresh(client, application, narrowed["refresh_token"], scope="read payment")
    assert response.status_code == 400
    assert json.loads(response.content.decode("utf-8"))["error"] == "invalid_scope"


def test_client_supplied_parameters_are_not_proof(client, application, test_user, clock):
    """Self-reported values, however named, change nothing."""
    log_in(client, test_user)
    forged = json.dumps({"level": "strong", "authenticated_at": T0.timestamp()})

    # At the authorization endpoint.
    login_redirect(authorize(client, application, auth_proof=forged, authentication=forged))

    # At the token endpoint: a real grant, a stale proof, a forged parameter.
    record_proof(client, "strong")
    code = consent(client, application)
    clock.return_value = datetime.fromtimestamp(T0.timestamp() + 301, tz=datetime_timezone.utc)
    response = exchange_code(client, application, code, auth_proof=forged, authentication=forged)
    assert response.status_code == 200
    assert json.loads(response.content.decode("utf-8"))["scope"] == "read"


def test_client_credentials_gets_no_sensitive_scope(client, application, clock):
    """A grant with no end-user authentication carries no proof at all."""
    application.authorization_grant_type = Application.GRANT_CLIENT_CREDENTIALS
    application.save()
    auth_headers = get_basic_auth_header(application.client_id, CLEARTEXT_SECRET)
    response = post_form(
        client,
        reverse("oauth2_provider:token"),
        data={"grant_type": "client_credentials", "scope": "read payment"},
        **auth_headers,
    )
    assert response.status_code == 200
    assert json.loads(response.content.decode("utf-8"))["scope"] == "read"


class TestProofBackend:
    """The extension point itself: recording, reading, and validation."""

    def test_recorded_proof_is_read_back(self, client, test_user, clock):
        log_in(client, test_user)
        record_proof(client, "strong")

        request = RequestFactory().get("/")
        request.session = client.session
        proof = SessionAuthenticationProofBackend().get_proof(request)
        assert proof == AuthenticationProof(level="strong", authenticated_at=T0)

    def test_no_session_or_no_record_means_no_proof(self, clock):
        request = RequestFactory().get("/")
        assert SessionAuthenticationProofBackend().get_proof(request) is None

    @pytest.mark.parametrize(
        "stored",
        ["strong", {"level": "strong"}, {"level": "", "authenticated_at": 1}, 42],
    )
    def test_malformed_session_data_is_ignored(self, client, test_user, stored, clock):
        log_in(client, test_user)
        session = client.session
        session[AUTHENTICATION_PROOF_SESSION_KEY] = stored
        session.save()

        request = RequestFactory().get("/")
        request.session = client.session
        assert SessionAuthenticationProofBackend().get_proof(request) is None

    def test_recording_an_unknown_level_is_rejected(self, client, test_user, clock):
        log_in(client, test_user)
        request = RequestFactory().get("/")
        request.session = client.session
        with pytest.raises(ValueError, match="AUTHENTICATION_PROOF_LEVELS"):
            record_authentication_proof(request, "nonexistent")

    @pytest.mark.parametrize(
        "requirements",
        [
            ["not", "a", "mapping"],
            {"payment": "strong"},
            {"payment": {"strength": "strong"}},
            {"payment": {"level": "unknown"}},
            {"payment": {"max_age_seconds": -1}},
        ],
    )
    def test_misconfigured_requirements_fail_loudly(self, requirements, oauth2_settings):
        oauth2_settings.SCOPE_AUTHENTICATION_REQUIREMENTS = requirements
        with pytest.raises(ImproperlyConfigured):
            authentication.scope_authentication_requirements()
