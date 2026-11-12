"""The consent page's permission list, and what an approval actually grants.

The End-User consents to scope identifiers, not to the text that describes them:
two scopes may share a description, and that description may be translated or
configured at runtime. The tests below check the final authorization record (the
Grant and, after a code exchange, the AccessToken), not just the rendered HTML.
"""

from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy, override

from oauth2_provider.authorization_server import consent
from oauth2_provider.core.scopes import UNRELIABLE_SCOPE_DESCRIPTION, BaseScopes, SettingsScopes
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_grant_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import post_form


Application = get_application_model()
Grant = get_grant_model()
AccessToken = get_access_token_model()
DeviceGrant = get_device_grant_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
REDIRECT_URI = "http://example.org"

# Two distinct scopes with the *same* human-readable text. ``read`` and
# ``write`` are also declared so the read/write helpers keep working.
SAME_TEXT_SCOPES = {
    "read": "Access your account",
    "write": "Access your account",
    "photos.read": "Read your photos",
    "photos.write": "Write your photos",
}


def _query(application, scope="read write", **extra):
    params = {
        "client_id": application.client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": "random_state_string",
    }
    params.update(extra)
    return params


def _consent_fields(page, **overrides):
    """The fields a browser posts back from the rendered consent page."""
    fields = {name: value for name, value in page.context_data["form"].initial.items() if value is not None}
    fields.update(overrides)
    return fields


def _redirect_params(response):
    assert response.status_code == 302, response.content
    location = urlparse(response["Location"])
    return parse_qs(location.fragment or location.query)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class ConsentTestBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("consent_user", "consent@example.com", "123456")
        cls.application = Application.objects.create(
            name="Consent Application",
            redirect_uris=REDIRECT_URI,
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def setUp(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        self.oauth2_settings.DEFAULT_SCOPES = ["read", "write"]
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="consent_user", password="123456")

    def open_page(self, scope="read write", **extra):
        response = self.client.get(
            reverse("oauth2_provider:authorize"), data=_query(self.application, scope, **extra)
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response

    def approve(self, page, **overrides):
        response = self.client.post(
            reverse("oauth2_provider:authorize"), data=_consent_fields(page, allow=True, **overrides)
        )
        return response

    def grant_scope(self):
        return Grant.objects.latest("id").scope


class TestTwoScopesWithTheSameText(ConsentTestBase):
    def test_the_page_lists_the_scope_identifiers_beside_the_shared_text(self):
        page = self.open_page("read write")
        permissions = page.context_data["scope_permissions"]
        self.assertEqual([permission.scope for permission in permissions], ["read", "write"])
        self.assertEqual([permission.description for permission in permissions], ["Access your account"] * 2)
        html = page.content.decode()
        self.assertIn("<code class=\"scope-name\">read</code>", html)
        self.assertIn("<code class=\"scope-name\">write</code>", html)

    def test_the_grant_records_the_selected_identifiers_not_the_text(self):
        page = self.open_page("read write")
        params = _redirect_params(self.approve(page))
        self.assertIn("code", params)
        # Exactly the identifiers that were offered, in the order they were shown.
        self.assertEqual(self.grant_scope(), "read write")

    def test_the_displayed_text_in_the_scope_field_grant_nothing_extra(self):
        # A client can report any text in the visible ``scope`` field, but the grant
        # is the signed identifier list, so the text never selects a permission.
        page = self.open_page("read")
        response = self.approve(page, scope="Access your account")
        params = _redirect_params(response)
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "read")

    def test_the_displayed_text_is_not_a_scope_without_a_signed_list(self):
        # Without the signed list (a hand-rolled consent form), the field is the
        # only source, but it is still validated as a scope identifier: the displayed
        # text is not one, so nothing is granted.
        page = self.open_page("read")
        fields = _consent_fields(page, allow=True, scope="Access your account")
        fields.pop("scope_details")
        response = self.client.post(reverse("oauth2_provider:authorize"), data=fields)
        params = _redirect_params(response)
        self.assertEqual(params["error"], ["invalid_scope"])
        self.assertFalse(Grant.objects.exists())

    def test_the_scope_field_cannot_add_scopes_beyond_the_signed_list(self):
        page = self.open_page("read")
        # photos.write was never shown; claiming it in the visible ``scope`` field
        # must not add it, because approval grants the signed list.
        response = self.approve(page, scope="read photos.write")
        params = _redirect_params(response)
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "read")

    def test_a_repeated_scope_is_shown_once_and_granted_by_identifier(self):
        page = self.open_page("read read")
        permissions = page.context_data["scope_permissions"]
        self.assertEqual([permission.scope for permission in permissions], ["read"])
        self.assertIn("code", _redirect_params(self.approve(page)))
        self.assertEqual(set(self.grant_scope().split()), {"read"})

    def test_the_scope_field_cannot_swap_the_granted_scope(self):
        page = self.open_page("read")
        response = self.approve(page, scope="write")
        params = _redirect_params(response)
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "read")

    def test_an_edited_signed_list_is_refused(self):
        page = self.open_page("read")
        fields = _consent_fields(page, allow=True)
        # A signature from a page showing ``read`` re-labelled to show two scopes.
        signature = fields["scope_details"]
        fields["scope_details"] = signature[:-1] + ("A" if signature[-1] != "A" else "B")
        response = self.client.post(reverse("oauth2_provider:authorize"), data=fields)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)
        self.assertFalse(Grant.objects.exists())

    def test_a_list_signed_for_another_request_is_refused(self):
        other = self.open_page("read", state="another_state")
        page = self.open_page("read")
        fields = _consent_fields(page, allow=True)
        fields["scope_details"] = other.context_data["form"].initial["scope_details"]
        response = self.client.post(reverse("oauth2_provider:authorize"), data=fields)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())


class TestLanguageSwitch(ConsentTestBase):
    """A translated description keeps its identity, so switching language does not
    invalidate a consent, and the grant is still keyed by the scope identifier."""

    def test_a_lazy_description_configured_in_settings_is_accepted(self):
        # SCOPES may hold gettext_lazy values, as its docs say. The default backend
        # must not mistake them for "no description".
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "photos.read": gettext_lazy("Yes")}
        page = self.open_page("photos.read")
        permission = page.context_data["scope_permissions"][0]
        self.assertTrue(permission.available)
        self.assertEqual(permission.identity, "i18n:Yes")
        self.assertEqual(permission.description, "Yes")
        params = _redirect_params(self.approve(page))
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "photos.read")

    def test_the_translated_text_is_shown_in_the_active_language(self):
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "photos.read": gettext_lazy("Yes")}
        with override("fr"):
            page = self.open_page("photos.read")
            self.assertEqual(page.context_data["scope_permissions"][0].description, "Oui")
            self.assertContains(page, "Oui")

    def test_a_browser_language_switch_keeps_the_consent_valid(self):
        # Negotiate the language the way a browser does, through LocaleMiddleware.
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "photos.read": gettext_lazy("Yes")}
        middleware = list(settings.MIDDLEWARE)
        middleware.insert(1, "django.middleware.locale.LocaleMiddleware")
        with override_settings(
            MIDDLEWARE=middleware,
            LANGUAGES=[("en", "English"), ("fr", "Français")],
        ):
            page_en = self.client.get(
                reverse("oauth2_provider:authorize"),
                data=_query(self.application, "photos.read"),
                HTTP_ACCEPT_LANGUAGE="en",
            )
            page_fr = self.client.get(
                reverse("oauth2_provider:authorize"),
                data=_query(self.application, "photos.read"),
                HTTP_ACCEPT_LANGUAGE="fr",
            )
            self.assertEqual(page_en.context_data["scope_permissions"][0].description, "Yes")
            self.assertEqual(page_fr.context_data["scope_permissions"][0].description, "Oui")
            # The same permission list is signed in both languages, so a page that
            # switched language between render and POST still approves the same scope.
            self.assertEqual(
                page_en.context_data["form"].initial["scope_details"],
                page_fr.context_data["form"].initial["scope_details"],
            )
            response = self.client.post(
                reverse("oauth2_provider:authorize"),
                data=_consent_fields(page_en, allow=True),
                HTTP_ACCEPT_LANGUAGE="fr",
            )
        self.assertIn("code", _redirect_params(response))
        self.assertEqual(self.grant_scope(), "photos.read")

    def test_a_translated_description_keeps_its_identity(self):
        lazy = gettext_lazy("Read your photos")
        self.assertEqual(consent.description_identity(lazy), "i18n:Read your photos")
        with override("fr"):
            self.assertEqual(consent.description_identity(lazy), "i18n:Read your photos")

    def test_a_translation_is_not_the_binding_key(self):
        # The same message id rendered in two languages has one identity.
        with override("fr"):
            french = str(gettext_lazy("Yes"))
        self.assertEqual(french, "Oui")
        self.assertNotEqual(french, "Yes")
        self.assertEqual(consent.description_identity(gettext_lazy("Yes")), "i18n:Yes")

    def test_switching_language_does_not_change_the_granted_scope(self):
        page = self.open_page("photos.read")
        first = _consent_fields(page, allow=True)
        with override("fr"):
            # A fresh page in another language signs the same identifiers.
            second_page = self.open_page("photos.read")
            self.assertEqual(first["scope_details"], _consent_fields(second_page)["scope_details"])
            response = self.approve(second_page)
        params = _redirect_params(response)
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "photos.read")

    def test_the_granted_scope_is_the_identifier_whatever_the_language(self):
        page = self.open_page("photos.read")
        with override("es"):
            response = self.approve(page)
        # Even a submission approved outside the rendering language grants the
        # identifier, never the translated text.
        params = _redirect_params(response)
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "photos.read")


class TestConfigurationChangesWhileThePageIsOpen(ConsentTestBase):
    def test_an_edited_description_is_refused(self):
        page = self.open_page("photos.read")
        # An administrator renames the scope's description after the page was shown.
        self.oauth2_settings.SCOPES = {
            **SAME_TEXT_SCOPES,
            "photos.read": "Permanently delete your photos",
        }
        response = self.client.post(
            reverse("oauth2_provider:authorize"), data=_consent_fields(page, allow=True)
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())
        self.assertContains(response, "changed while the consent page was open", status_code=400)

    def test_a_removed_description_is_refused(self):
        page = self.open_page("photos.read")
        self.oauth2_settings.SCOPES = {"read": "Access your account", "write": "Access your account"}
        response = self.client.post(
            reverse("oauth2_provider:authorize"), data=_consent_fields(page, allow=True)
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())

    def test_a_scope_added_after_the_page_was_shown_is_not_granted(self):
        page = self.open_page("read")
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "admin": "Delete everything"}
        response = self.approve(page, scope="read admin")
        params = _redirect_params(response)
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "read")

    def test_a_description_with_the_same_text_for_another_scope_is_still_refused(self):
        # Editing one scope's text to another's is a change, even though the text
        # shown would read the same.
        page = self.open_page("photos.read")
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "photos.read": SAME_TEXT_SCOPES["photos.write"]}
        response = self.client.post(
            reverse("oauth2_provider:authorize"), data=_consent_fields(page, allow=True)
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())


class TestUnreliableDescriptions(ConsentTestBase):
    """A permission whose text cannot be vouched for is not granted."""

    def _page_with_scope(self, scope):
        # The scope is available and requested, but no description has been
        # configured for it yet: exactly the state of a newly added sensitive scope.
        self.oauth2_settings.SCOPES_BACKEND_CLASS = MissingDescriptionScopes
        page = self.open_page(scope)
        self.assertEqual(page.status_code, 200)
        return page

    def test_a_missing_description_is_shown_as_withheld(self):
        page = self._page_with_scope("photos.read")
        permission = page.context_data["scope_permissions"][0]
        self.assertEqual(permission.scope, "photos.read")
        self.assertFalse(permission.available)
        self.assertIsNone(permission.identity)
        self.assertContains(page, "This permission cannot be granted")

    def test_approving_a_withheld_scope_is_refused(self):
        page = self._page_with_scope("photos.read")
        response = self.approve(page, scope="photos.read")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())
        self.assertContains(response, "cannot be described reliably", status_code=400)

    def test_a_blank_description_is_withheld(self):
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "photos.read": "   "}
        page = self.open_page("read photos.read")
        self.assertFalse(page.context_data["scope_permissions"][1].available)

    def test_a_backend_error_withholds_the_scope(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        failure = mock.patch.object(
            SettingsScopes, "get_scope_description", side_effect=RuntimeError("backend down")
        )
        with failure:
            page = self.open_page("read")
        self.assertFalse(page.context_data["scope_permissions"][0].available)
        response = self.approve(page, scope="read")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())

    def test_a_non_string_description_is_withheld(self):
        self.oauth2_settings.SCOPES = {**SAME_TEXT_SCOPES, "photos.read": 42}
        page = self.open_page("read photos.read")
        self.assertFalse(page.context_data["scope_permissions"][1].available)

    def test_a_trusted_application_still_gets_only_described_scopes(self):
        # skip_authorization grants without a page: there is no text to bind, and
        # the request is validated by oauthlib as before.
        self.oauth2_settings.SCOPES = {"read": "Access your account", "write": "Access your account"}
        self.oauth2_settings.PKCE_REQUIRED = False
        self.application.skip_authorization = True
        self.application.save()
        response = self.client.get(
            reverse("oauth2_provider:authorize"), data=_query(self.application, "read write")
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.grant_scope(), "read write")


class TestCustomBackendDescriptions(ConsentTestBase):
    """A custom backend can supply the text, per application and per request."""

    def test_the_backend_decides_the_text_shown_and_its_identity(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        self.oauth2_settings.SCOPES_BACKEND_CLASS = RequestAwareScopes
        page = self.open_page("photos.read")
        permission = page.context_data["scope_permissions"][0]
        self.assertEqual(permission.description, "Custom text for photos.read")
        self.assertEqual(permission.identity, "text:Custom text for photos.read")
        params = _redirect_params(self.approve(page))
        self.assertIn("code", params)
        self.assertEqual(self.grant_scope(), "photos.read")

    def test_a_backend_that_changes_its_text_invalidates_the_consent(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        self.oauth2_settings.SCOPES_BACKEND_CLASS = ChangingScopes
        ChangingScopes.text = "First text"
        page = self.open_page("read")
        ChangingScopes.text = "Second text"
        response = self.approve(page)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())

    def test_a_backend_that_returns_none_withholds_the_scope(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        self.oauth2_settings.SCOPES_BACKEND_CLASS = NoDescriptionScopes
        page = self.open_page("read")
        self.assertFalse(page.context_data["scope_permissions"][0].available)
        response = self.approve(page, scope="read")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Grant.objects.exists())


class RequestAwareScopes(BaseScopes):
    def get_all_scopes(self):
        return dict(SAME_TEXT_SCOPES)

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        return list(SAME_TEXT_SCOPES)

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        return ["read", "write"]

    def get_scope_description(self, scope, application=None, request=None, *args, **kwargs):
        return f"Custom text for {scope}"


class ChangingScopes(RequestAwareScopes):
    text = "First text"

    def get_scope_description(self, scope, application=None, request=None, *args, **kwargs):
        return ChangingScopes.text


class NoDescriptionScopes(RequestAwareScopes):
    def get_scope_description(self, scope, application=None, request=None, *args, **kwargs):
        return None


class MissingDescriptionScopes(RequestAwareScopes):
    """Every scope is offered, but descriptions exist only for some."""

    DESCRIBED = {"read", "write"}

    def get_scope_description(self, scope, application=None, request=None, *args, **kwargs):
        if scope not in self.DESCRIBED:
            return None
        return SAME_TEXT_SCOPES[scope]


class TestCodeExchangeKeepsTheScope(ConsentTestBase):
    """The final record after a full flow: the AccessToken carries the identifier."""

    def test_the_access_token_scope_comes_from_the_signed_list(self):
        page = self.open_page("photos.read")
        # Swap the visible scope field for another, same-text scope.
        response = self.approve(page, scope="photos.write")
        params = _redirect_params(response)
        self.assertIn("code", params)
        code = params["code"][0]

        token_response = post_form(
            self.client,
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
            },
        )
        self.assertEqual(token_response.status_code, 200, token_response.content)
        self.assertEqual(token_response.json()["scope"], "photos.read")
        token = AccessToken.objects.get()
        self.assertEqual(token.scope, "photos.read")
        self.assertNotIn("photos.write", token.scope)

    def test_the_authorization_code_carries_the_identifier_not_the_text(self):
        page = self.open_page("read")
        response = self.approve(page, scope="Access your account")
        params = _redirect_params(response)
        self.assertIn("code", params)
        grant = Grant.objects.get()
        self.assertEqual(grant.scope, "read")
        self.assertNotIn("Access your account", grant.scope)


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DEFAULT_SCOPES_RW)
class TestDeviceConsentShowsThePermissions(TestCase):
    """RFC 8628: the user approves scopes at a verification page, so the same
    identifier/description rules apply there."""

    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("device_user", "device@example.com", "123456")
        cls.application = Application.objects.create(
            name="Device Application",
            user=cls.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_DEVICE_CODE,
        )

    def setUp(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        self.oauth2_settings.DEFAULT_SCOPES = ["read", "write"]
        self.client.login(username="device_user", password="123456")

    def _device_grant(self, scope):
        return DeviceGrant.objects.create(
            client_id=self.application.client_id,
            device_code="device_code",
            user_code="user_code",
            scope=scope,
            expires=timezone.now() + timedelta(days=1),
            status=DeviceGrant.AUTHORIZATION_PENDING,
            user=self.user,
        )

    def _confirm_url(self):
        return reverse(
            "oauth2_provider:device-confirm",
            kwargs={"user_code": "user_code", "client_id": self.application.client_id},
        )

    def test_two_scopes_with_the_same_text_are_shown_by_identifier(self):
        self._device_grant("read write")
        page = self.client.get(self._confirm_url())
        permissions = page.context_data["scope_permissions"]
        self.assertEqual([permission.scope for permission in permissions], ["read", "write"])
        self.assertEqual([permission.description for permission in permissions], ["Access your account"] * 2)

    def test_accepting_a_withheld_permission_is_refused(self):
        self._device_grant("photos.read")
        self.oauth2_settings.SCOPES_BACKEND_CLASS = MissingDescriptionScopes
        page = self.client.get(self._confirm_url())
        self.assertFalse(page.context_data["scope_permissions"][0].available)
        response = self.client.post(self._confirm_url(), data={"action": "accept"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DeviceGrant.objects.get().status, DeviceGrant.AUTHORIZATION_PENDING)

    def test_accepting_described_permissions_authorizes_the_grant(self):
        self._device_grant("read write")
        response = self.client.post(self._confirm_url(), data={"action": "accept"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(DeviceGrant.objects.get().status, DeviceGrant.AUTHORIZED)


class TestPermissionsComeFromTheBackend(ConsentTestBase):
    """The permission list is computed once and used for both rendering and binding."""

    def test_the_backend_can_vary_descriptions_by_application(self):
        self.oauth2_settings.SCOPES = dict(SAME_TEXT_SCOPES)
        self.oauth2_settings.SCOPES_BACKEND_CLASS = ApplicationScopedDescriptions
        page = self.open_page("photos.read")
        permission = page.context_data["scope_permissions"][0]
        self.assertEqual(permission.description, f"Custom text for {self.application.name}")

    def test_a_scope_without_a_description_is_reported_with_its_identifier(self):
        self.oauth2_settings.SCOPES_BACKEND_CLASS = MissingDescriptionScopes
        page = self.open_page("photos.read")
        permission = page.context_data["scope_permissions"][0]
        self.assertEqual(permission.scope, "photos.read")
        self.assertEqual(permission.description, str(UNRELIABLE_SCOPE_DESCRIPTION))

    def test_the_identifier_is_not_used_as_a_fallback_description(self):
        # A scope name is not a description: it says nothing about what is granted.
        # The page shows the withheld notice instead, and the permission cannot be
        # approved.
        self.oauth2_settings.SCOPES_BACKEND_CLASS = MissingDescriptionScopes
        page = self.open_page("photos.read")
        self.assertNotIn("photos.read</span>", page.content.decode())
        self.assertContains(page, "This permission cannot be granted")
        self.assertFalse(page.context_data["scope_permissions"][0].available)


class ApplicationScopedDescriptions(BaseScopes):
    def get_all_scopes(self):
        return dict(SAME_TEXT_SCOPES)

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        return list(SAME_TEXT_SCOPES)

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        return ["read", "write"]

    def get_scope_description(self, scope, application=None, request=None, *args, **kwargs):
        return f"Custom text for {application.name}"
