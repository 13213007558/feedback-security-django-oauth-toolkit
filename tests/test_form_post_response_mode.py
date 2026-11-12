"""
Tests for the optional OAuth 2.0 Form Post Response Mode
(https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).

The authorization endpoint answers ``response_mode=form_post`` with an
auto-submitting HTML form that POSTs the response parameters to the registered
redirect URI, so the parameters never enter a URL. Successful responses and the
errors that may be returned to the client go through the same target validation;
requests whose redirect URI cannot be trusted stay on the authorization server.
"""

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from oauth2_provider.models import get_application_model

from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header, post_form


Application = get_application_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


class FormPostHTMLParser(HTMLParser):
    """Collect the form action, method and hidden controls of a Form Post page."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None
        self.hidden_inputs = []
        self.submits = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current = {"action": attrs.get("action", ""), "method": attrs.get("method", "")}
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            if attrs.get("type") == "hidden":
                self.hidden_inputs.append((attrs.get("name", ""), attrs.get("value", "")))
            elif attrs.get("type") == "submit":
                self.submits.append(attrs.get("value", ""))
        elif tag == "a":
            self.links.append(attrs.get("href", ""))


@pytest.mark.usefixtures("oauth2_settings")
class BaseFormPostTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="Test Form Post Application",
            redirect_uris=(
                "http://localhost http://example.com http://example.org "
                "custom-scheme://example.com http://example.org/callback "
                "http://example.org?foo=bar"
            ),
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret="1234567890abcdefghijklmnopqrstuvwxyz",
        )

    def setUp(self):
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["http", "custom-scheme"]
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

    def authorize_url(self, **overrides):
        query = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "response_mode": "form_post",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org/callback",
        }
        query.update(overrides)
        return reverse("oauth2_provider:authorize"), query

    def parse(self, response):
        parser = FormPostHTMLParser()
        parser.feed(response.content.decode())
        return parser

    def hidden(self, response):
        return dict(self.parse(response).hidden_inputs)


class TestFormPostSuccess(BaseFormPostTestCase):
    def test_success_renders_form_post_to_registered_redirect_uri(self):
        url, query = self.authorize_url()
        response = self.client.get(url, data=query)
        # The consent page is rendered first; consent then produces the Form Post page.
        self.assertEqual(response.status_code, 200)
        self.assertIn("form", response.context)

        form_data = {**query, "allow": True}
        response = self.client.post(url, data=form_data)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response)
        parser = self.parse(response)
        self.assertEqual(len(parser.forms), 1)
        self.assertEqual(parser.forms[0]["method"].lower(), "post")
        self.assertEqual(parser.forms[0]["action"], "http://example.org/callback")

        fields = dict(parser.hidden_inputs)
        self.assertIn("code", fields)
        self.assertTrue(fields["code"])
        self.assertEqual(fields["state"], "random_state_string")

    def test_form_post_fields_are_not_in_the_url(self):
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": True})

        self.assertEqual(response.status_code, 200)
        parser = self.parse(response)
        parsed_action = urlparse(parser.forms[0]["action"])
        self.assertEqual(parsed_action.query, "")
        self.assertEqual(parsed_action.fragment, "")
        # No response parameter anywhere in a redirect location.
        self.assertNotIn("Location", response)

    def test_skip_authorization_application_returns_form_post(self):
        self.application.skip_authorization = True
        self.application.save()
        url, query = self.authorize_url()

        response = self.client.get(url, data=query)

        self.assertEqual(response.status_code, 200)
        parser = self.parse(response)
        self.assertEqual(parser.forms[0]["action"], "http://example.org/callback")
        self.assertIn("code", dict(parser.hidden_inputs))

    def test_custom_scheme_target_uses_same_validation_as_redirects(self):
        url, query = self.authorize_url(redirect_uri="custom-scheme://example.com")
        response = self.client.post(url, data={**query, "allow": True})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.parse(response).forms[0]["action"], "custom-scheme://example.com")

    def test_iss_parameter_is_a_field_not_part_of_the_action(self):
        self.oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS = True
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": True})

        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('action="http://example.org/callback"', body)
        self.assertIn('name="iss"', body)
        self.assertNotIn("http://example.org/callback?", body)


class TestFormPostErrors(BaseFormPostTestCase):
    def test_user_denial_is_posted_back_as_access_denied(self):
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": False})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response)
        parser = self.parse(response)
        self.assertEqual(parser.forms[0]["method"].lower(), "post")
        self.assertEqual(parser.forms[0]["action"], "http://example.org/callback")
        fields = dict(parser.hidden_inputs)
        self.assertEqual(fields["error"], "access_denied")
        self.assertEqual(fields["state"], "random_state_string")

    def test_denial_without_state_posts_no_state_field(self):
        url, query = self.authorize_url(state=None)
        del query["state"]
        response = self.client.post(url, data={**query, "allow": False})

        fields = self.hidden(response)
        self.assertEqual(fields["error"], "access_denied")
        self.assertNotIn("state", fields)

    def test_unregistered_redirect_uri_is_not_posted_to(self):
        url, query = self.authorize_url(redirect_uri="http://attacker.example/cb")
        response = self.client.post(url, data={**query, "allow": True})

        # The target failed callback validation: the error stays in the site,
        # and no form points at the unregistered URI.
        self.assertNotEqual(response.status_code, 302)
        body = response.content.decode()
        self.assertNotIn("http://attacker.example/cb", body)
        self.assertNotIn("<form", body)

    def test_invalid_resource_error_is_posted_to_the_registered_uri(self):
        url, query = self.authorize_url(resource="not-an-absolute-uri")
        response = self.client.get(url, data=query)

        self.assertEqual(response.status_code, 200)
        parser = self.parse(response)
        self.assertEqual(parser.forms[0]["action"], "http://example.org/callback")
        fields = dict(parser.hidden_inputs)
        self.assertEqual(fields["error"], "invalid_target")
        self.assertEqual(fields["state"], "random_state_string")


class TestFormPostEncoding(BaseFormPostTestCase):
    def test_special_characters_are_html_escaped_in_fields_and_action(self):
        special_state = "<b>\"&'<>"
        url, query = self.authorize_url(state=special_state)
        response = self.client.post(url, data={**query, "allow": False})

        body = response.content.decode()
        # The raw characters must not appear unescaped in the HTML.
        self.assertNotIn("<b>", body)
        parser = self.parse(response)
        fields = dict(parser.hidden_inputs)
        self.assertEqual(fields["state"], special_state)
        self.assertEqual(fields["error"], "access_denied")

    def test_spaces_and_unicode_round_trip_through_hidden_controls(self):
        special_state = "state with spaces and éü中文"
        url, query = self.authorize_url(state=special_state)
        response = self.client.post(url, data={**query, "allow": False})

        self.assertEqual(self.hidden(response)["state"], special_state)

    def test_query_string_in_redirect_uri_is_preserved_on_action(self):
        url, query = self.authorize_url(redirect_uri="http://example.org?foo=bar")
        response = self.client.post(url, data={**query, "allow": True})

        parser = self.parse(response)
        # The registered URI keeps its own query; response params are form fields.
        self.assertEqual(parser.forms[0]["action"], "http://example.org?foo=bar")
        fields = dict(parser.hidden_inputs)
        self.assertIn("code", fields)
        self.assertNotIn("code", urlparse(parser.forms[0]["action"]).query)


class TestFormPostHeadersAndLeakage(BaseFormPostTestCase):
    def test_cache_and_referrer_headers(self):
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": True})

        self.assertEqual(response["Cache-Control"], "no-store, no-cache")
        self.assertEqual(response["Pragma"], "no-cache")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")

    def test_page_has_no_link_or_diagnostic_copying_the_credentials(self):
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": True})

        body = response.content.decode()
        parser = self.parse(response)
        self.assertEqual(parser.links, [])
        code = self.hidden(response)["code"]
        # The authorization code appears only in its hidden control, nowhere else.
        self.assertEqual(len(re.findall(re.escape(code), body)), 1)
        # No anchor, no extra form, no JavaScript carrying the parameters.
        self.assertEqual(len(parser.forms), 1)

    def test_noscript_offers_a_submit_button(self):
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": True})

        parser = self.parse(response)
        # A no-script user agent can still submit the form manually.
        self.assertEqual(len(parser.submits), 1)

    def test_page_auto_submits_the_form(self):
        url, query = self.authorize_url()
        response = self.client.post(url, data={**query, "allow": True})

        self.assertIn("onload", response.content.decode())


class TestFormPostLoginRecovery(BaseFormPostTestCase):
    def test_form_post_survives_the_login_redirect(self):
        self.client.logout()
        url, query = self.authorize_url()

        # Anonymous: the view redirects to the login page, keeping the whole request.
        response = self.client.get(url, data=query)
        self.assertEqual(response.status_code, 302)
        login_url = response["Location"]
        self.assertIn("response_mode%3Dform_post", login_url)

        # The login page authenticates the user and sends the browser back to the
        # authorization request recorded in the login "next" parameter.
        next_url = parse_qs(urlparse(login_url).query)["next"][0]
        self.client.force_login(self.test_user)
        response = self.client.get(next_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("form", response.context)

        form_data = {**query, "allow": True}
        response = self.client.post(url, data=form_data)
        self.assertEqual(response.status_code, 200)
        parser = self.parse(response)
        self.assertEqual(parser.forms[0]["action"], "http://example.org/callback")
        self.assertIn("code", dict(parser.hidden_inputs))


class TestFormPostDisabled(BaseFormPostTestCase):
    def test_disabled_mode_is_rejected_without_redirect_or_form(self):
        self.oauth2_settings.FORM_POST_RESPONSE_MODE_ENABLED = False
        url, query = self.authorize_url()

        response = self.client.get(url, data=query)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)
        self.assertNotIn("<form", response.content.decode())

    def test_disabled_mode_rejects_consent_post_too(self):
        self.oauth2_settings.FORM_POST_RESPONSE_MODE_ENABLED = False
        url, query = self.authorize_url()

        response = self.client.post(url, data={**query, "allow": True})

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)


@pytest.mark.usefixtures("oauth2_settings")
class TestFormPostImplicitFlow(TestCase):
    """Form Post is also valid for front-channel response types."""

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("implicit_user", "implicit@example.com", "123456")
        cls.application = Application.objects.create(
            name="Test Implicit Form Post Application",
            redirect_uris="http://example.org",
            user=cls.test_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
        )

    def setUp(self):
        self.client.login(username="implicit_user", password="123456")

    def test_token_response_is_posted_not_put_in_fragment(self):
        query = {
            "client_id": self.application.client_id,
            "response_type": "token",
            "response_mode": "form_post",
            "state": "random_state_string",
            "scope": "read write",
            "redirect_uri": "http://example.org",
        }
        url = reverse("oauth2_provider:authorize")
        response = self.client.post(url, data={**query, "allow": True})

        self.assertEqual(response.status_code, 200)
        parser = FormPostHTMLParser()
        parser.feed(response.content.decode())
        self.assertEqual(parser.forms[0]["action"], "http://example.org")
        self.assertEqual(urlparse(parser.forms[0]["action"]).fragment, "")
        fields = dict(parser.hidden_inputs)
        self.assertIn("access_token", fields)
        self.assertEqual(fields["token_type"], "Bearer")
        self.assertEqual(fields["state"], "random_state_string")
        self.assertEqual(response["Cache-Control"], "no-store, no-cache")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")


@pytest.mark.usefixtures("oauth2_settings")
class TestFormPostPushedAuthorizationRequest(BaseFormPostTestCase):
    """form_post survives a pushed authorization request (RFC 9126)."""

    def push(self):
        response = post_form(
            self.client,
            reverse("oauth2_provider:pushed-authorization-request"),
            data={
                "client_id": self.application.client_id,
                "response_type": "code",
                "response_mode": "form_post",
                "redirect_uri": "http://example.org/callback",
                "scope": "read write",
                "state": "par_state",
            },
            **get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET),
        )
        self.assertEqual(response.status_code, 201)
        return response.json()["request_uri"]

    def test_stored_request_posts_the_code_to_the_registered_uri(self):
        request_uri = self.push()
        authorize_url = reverse("oauth2_provider:authorize")
        reference = {"client_id": self.application.client_id, "request_uri": request_uri}

        # The browser only carries client_id and request_uri; the mode lives in the store.
        consent_page = self.client.get(authorize_url, data=reference)
        self.assertEqual(consent_page.status_code, 200)
        self.assertIn("form", consent_page.context)
        # The hidden form keeps the mode so the consent POST honours it.
        self.assertEqual(consent_page.context["form"]["response_mode"].value(), "form_post")

        # The consent submission posts the hidden fields back alongside the reference.
        form_data = {
            key: value
            for key, value in consent_page.context_data["form"].initial.items()
            if value is not None
        }
        form_data["allow"] = True
        response = self.client.post(authorize_url, data=form_data)

        self.assertEqual(response.status_code, 200)
        parser = self.parse(response)
        self.assertEqual(parser.forms[0]["action"], "http://example.org/callback")
        fields = dict(parser.hidden_inputs)
        self.assertIn("code", fields)
        self.assertEqual(fields["state"], "par_state")
        self.assertEqual(response["Cache-Control"], "no-store, no-cache")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")


@pytest.mark.usefixtures("oauth2_settings")
class TestFormPostDiscovery(BaseFormPostTestCase):
    def test_metadata_advertises_form_post_and_removes_it_when_disabled(self):
        url = reverse("oauth2_provider:oauth-server-metadata")

        response = self.client.get(url)
        self.assertEqual(response.json()["response_modes_supported"], ["query", "fragment", "form_post"])

        self.oauth2_settings.FORM_POST_RESPONSE_MODE_ENABLED = False
        response = self.client.get(url)
        self.assertEqual(response.json()["response_modes_supported"], ["query", "fragment"])
