import hashlib
import logging
import time
import uuid
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Callable, Optional, Union
from urllib.parse import urlparse, urlsplit

from django.apps import apps
from django.conf import settings
from django.contrib.auth.hashers import identify_hasher, make_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models, router, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from jwcrypto import jwk
from jwcrypto.common import JWException, base64url_encode
from oauthlib.oauth2.rfc6749 import errors

from .core.scopes import get_scopes_backend
from .core.utils import jwk_allows_verification, jwk_from_pem
from .generators import generate_client_id, generate_client_secret
from .settings import oauth2_settings

# AllowedURIValidator is re-exported for backwards compatibility. clean() no longer
# constructs one itself -- the validator is built by the REDIRECT_URI_VALIDATOR /
# ALLOWED_ORIGIN_VALIDATOR factories -- but the name has long been importable from here.
# Import it from oauth2_provider.validators in new code.
#
# Spelled as a redundant alias: that is the standard marker for a deliberate re-export
# (PEP 484), so linters read the intent from the code rather than from this comment.
from .validators import AllowedURIValidator as AllowedURIValidator  # noqa: F401


logger = logging.getLogger(__name__)


class ResourceJSONField(models.JSONField):
    """
    RFC 8707 - JSON array of resource URIs.

    Empty list means not restricted to specific resource servers (unrestricted access).
    """

    def pre_save(self, model_instance, add):
        """The field is not nullable; treat None as "no resource restriction"."""
        value = super().pre_save(model_instance, add)
        if value is None:
            value = []
            setattr(model_instance, self.attname, value)
        return value

    def get_db_prep_value(self, value, connection, prepared=False):
        """Validate before saving to database."""
        if value is not None:
            if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
                raise ValidationError("Resource must be a list of URI strings")
        return super().get_db_prep_value(value, connection, prepared)


class ClaimsRequestJSONField(models.JSONField):
    """
    The normalized OIDC ``claims`` request (Core 5.5) behind a token: a JSON object.

    An empty request is ``{}``, never ``NULL``, and anything but an object is refused.
    """

    def pre_save(self, model_instance: models.Model, add: bool) -> dict:
        """The field is not nullable; treat None as an empty claims request.

        The type is checked here, on save, rather than in ``get_db_prep_value``,
        which also prepares the scalar operands of key lookups such as
        ``claims__userinfo__name__essential=True``.
        """
        value = super().pre_save(model_instance, add)
        if value is None:
            value = {}
            setattr(model_instance, self.attname, value)
        if not isinstance(value, dict):
            raise ValidationError("The claims request must be a JSON object.")
        return value

    def validate(self, value: object, model_instance: models.Model) -> None:
        super().validate(value, model_instance)
        if value is not None and not isinstance(value, dict):
            raise ValidationError(_("The claims request must be a JSON object."), code="invalid")


class ClientSecretField(models.CharField):
    def pre_save(self, model_instance, add):
        secret = getattr(model_instance, self.attname)
        should_be_hashed = getattr(model_instance, "hash_client_secret", True)
        if not should_be_hashed:
            return super().pre_save(model_instance, add)

        try:
            hasher = identify_hasher(secret)
            logger.debug(f"{model_instance}: {self.attname} is already hashed with {hasher}.")
        except ValueError:
            logger.debug(f"{model_instance}: {self.attname} is not hashed; hashing it now.")
            hashed_secret = make_password(secret, hasher=oauth2_settings.CLIENT_SECRET_HASHER)
            setattr(model_instance, self.attname, hashed_secret)
            return hashed_secret
        return super().pre_save(model_instance, add)


class TokenChecksumField(models.CharField):
    def pre_save(self, model_instance, add):
        # RFC 9700 token storage: when the plaintext token is redacted at rest (see
        # COMPLIANT_BCP_RFC9700_TOKEN_STORAGE) the raw token is stashed
        # on ``_raw_token`` and the ``token`` column is left blank. The lookup checksum
        # is then computed from ``_raw_token``, which is cleared afterwards to minimize
        # the in-memory lifetime of a usable token value.
        raw_token = getattr(model_instance, "_raw_token", None)
        if raw_token is None:
            # No raw token available. On the plaintext-storage path the ``token``
            # column holds the raw token, so (re)derive the checksum from it. On the
            # hashed-at-rest path the column is blank on later saves (e.g.
            # ``RefreshToken.revoke()``); there is nothing to recompute, so the
            # existing checksum is kept instead of being hashed a second time.
            token = getattr(model_instance, "token")
            if not token:
                return super().pre_save(model_instance, add)
            raw_token = token
        else:
            model_instance._raw_token = None
        checksum = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        setattr(model_instance, self.attname, checksum)
        return super().pre_save(model_instance, add)


def set_token_value(token_instance: "AbstractAccessToken | AbstractRefreshToken", raw_token: str) -> None:
    """
    Assign the raw token to a token instance, redacting the value stored at rest
    when COMPLIANT_BCP_RFC9700_TOKEN_STORAGE is enabled (RFC 9700).

    The lookup checksum (``token_checksum``) is always derived from the raw token;
    when redacting, the raw value is stashed on ``_raw_token`` (used only to compute
    the checksum, see :class:`TokenChecksumField`) and the ``token`` column is left
    blank so the reusable token is never persisted.

    Plaintext storage is an ambient config posture exercised on every token
    issuance, so (unlike the request-time gates) it is surfaced by the ``--deploy``
    system check ``W006`` rather than a per-token warning here. See
    :mod:`oauth2_provider.bcp`.
    """
    if oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE:
        token_instance._raw_token = raw_token
        token_instance.token = ""
    else:
        token_instance.token = raw_token
        # Clear any stale redaction marker so a later save recomputes the checksum
        # from this plaintext token rather than a previously stashed raw value.
        token_instance._raw_token = None


class AbstractApplication(models.Model):
    """
    An Application instance represents a Client on the Authorization server.
    Usually an Application is created manually by client's developers after
    logging in on an Authorization Server.

    Fields:

    * :attr:`client_id` The client identifier issued to the client during the
                        registration process as described in :rfc:`2.2`
    * :attr:`user` ref to a Django user
    * :attr:`redirect_uris` The list of allowed redirect uri. The string
                            consists of valid URLs separated by space
    * :attr:`post_logout_redirect_uris` The list of allowed redirect uris after
                                        an RP initiated logout. The string
                                        consists of valid URLs separated by space
    * :attr:`client_type` Client type as described in :rfc:`2.1`
    * :attr:`authorization_grant_type` Authorization flows available to the
                                       Application
    * :attr:`client_secret` Confidential secret issued to the client during
                            the registration process as described in :rfc:`2.2`
    * :attr:`name` Friendly name for the Application
    * :attr:`registration_source` How the Application was registered: ``manual``
                                  for manually created Applications, ``dcr`` for
                                  those registered via Dynamic Client
                                  Registration (RFC 7591), ``cimd`` for Client
                                  ID Metadata Document
    * :attr:`cimd_expires_at` When the cached metadata document should be
                              re-fetched, for CIMD applications
    * :attr:`require_pushed_authorization_requests` Whether this client may only
                              start an authorization request via PAR (:rfc:`9126`).
                              ``None`` defers to the server-wide setting.
    * :attr:`can_introspect` Whether this client may call the token
                             introspection endpoint (:rfc:`7662`), with an access
                             token issued to it or, if it is confidential, by
                             authenticating as itself.
    * :attr:`userinfo_signed_response_alg` The JWS ``alg`` the UserInfo response is
                                           signed with (OpenID Connect Core 1.0
                                           section 5.3.2). Blank returns plain JSON.
    """

    class RegistrationSource(models.TextChoices):
        MANUAL = "manual", _("Manual")
        DCR = "dcr", _("Dynamic Client Registration")
        CIMD = "cimd", _("Client ID Metadata Document")
        # FEDERATION (OpenID Federation) reserved for future use

    CLIENT_CONFIDENTIAL = "confidential"
    CLIENT_PUBLIC = "public"
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _("Confidential")),
        (CLIENT_PUBLIC, _("Public")),
    )

    GRANT_AUTHORIZATION_CODE = "authorization-code"
    GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    GRANT_IMPLICIT = "implicit"
    GRANT_PASSWORD = "password"
    GRANT_CLIENT_CREDENTIALS = "client-credentials"
    GRANT_OPENID_HYBRID = "openid-hybrid"
    GRANT_TYPES = (
        (GRANT_AUTHORIZATION_CODE, _("Authorization code")),
        (GRANT_DEVICE_CODE, _("Device Code")),
        (GRANT_IMPLICIT, _("Implicit")),
        (GRANT_PASSWORD, _("Resource owner password-based")),
        (GRANT_CLIENT_CREDENTIALS, _("Client credentials")),
        (GRANT_OPENID_HYBRID, _("OpenID connect hybrid")),
    )

    NO_ALGORITHM = ""
    RS256_ALGORITHM = "RS256"
    HS256_ALGORITHM = "HS256"
    ALGORITHM_TYPES = (
        (NO_ALGORITHM, _("No OIDC support")),
        (RS256_ALGORITHM, _("RSA with SHA-2 256")),
        (HS256_ALGORITHM, _("HMAC with SHA-2 256")),
    )
    # OpenID Connect Core 1.0 section 5.3.2: UserInfo is plain JSON unless the client
    # registered a signing algorithm. Only RS256 with the server's OIDC_RSA_PRIVATE_KEY
    # is offered; HS256 would need the client secret in plaintext.
    USERINFO_ALGORITHM_TYPES = (
        (NO_ALGORITHM, _("No signing (JSON)")),
        (RS256_ALGORITHM, _("RSA with SHA-2 256")),
    )

    # RFC 7591 / OIDC token_endpoint_auth_method values. The blank default
    # keeps the legacy behavior: secret via Basic auth or request body for
    # confidential clients, nothing for public ones. JWT client assertions
    # (RFC 7523) are only accepted when explicitly registered.
    TOKEN_AUTH_METHOD_DEFAULT = ""
    TOKEN_AUTH_METHOD_NONE = "none"
    TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic"
    TOKEN_AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post"
    TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT = "client_secret_jwt"
    TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt"
    TOKEN_AUTH_METHODS = (
        (TOKEN_AUTH_METHOD_DEFAULT, _("Not set (infer from client type)")),
        (TOKEN_AUTH_METHOD_NONE, _("None (public client)")),
        (TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC, _("Client secret via HTTP Basic auth")),
        (TOKEN_AUTH_METHOD_CLIENT_SECRET_POST, _("Client secret in the request body")),
        (TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT, _("JWT assertion signed with the client secret")),
        (TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT, _("JWT assertion signed with a private key")),
    )
    JWT_AUTH_METHODS = (
        TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT,
        TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT,
    )

    id = models.BigAutoField(primary_key=True)
    # 255 rather than 100 so a Client ID Metadata Document URL fits (CIMD uses
    # the client's https URL as its client_id).
    client_id = models.CharField(
        max_length=255, unique=True, default=generate_client_id, db_index=True, verbose_name=_("client ID")
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="%(app_label)s_%(class)s",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        verbose_name=_("user"),
    )

    redirect_uris = models.TextField(
        blank=True,
        help_text=_("Allowed URIs list, space separated"),
        verbose_name=_("redirect URIs"),
    )
    post_logout_redirect_uris = models.TextField(
        blank=True,
        help_text=_("Allowed Post Logout URIs list, space separated"),
        default="",
        verbose_name=_("post logout redirect URIs"),
    )
    client_type = models.CharField(max_length=32, choices=CLIENT_TYPES, verbose_name=_("client type"))
    authorization_grant_type = models.CharField(
        max_length=44, choices=GRANT_TYPES, verbose_name=_("authorization grant type")
    )
    client_secret = ClientSecretField(
        max_length=255,
        blank=True,
        default=generate_client_secret,
        db_index=True,
        help_text=_("Client secret for authentication"),
        verbose_name=_("client secret"),
    )
    hash_client_secret = models.BooleanField(default=True, verbose_name=_("hash client secret"))
    name = models.CharField(max_length=255, blank=True, verbose_name=_("name"))
    skip_authorization = models.BooleanField(default=False, verbose_name=_("skip authorization"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))
    algorithm = models.CharField(
        max_length=5, choices=ALGORITHM_TYPES, default=NO_ALGORITHM, blank=True, verbose_name=_("algorithm")
    )
    userinfo_signed_response_alg = models.CharField(
        max_length=5,
        choices=USERINFO_ALGORITHM_TYPES,
        default=NO_ALGORITHM,
        blank=True,
        help_text=_(
            "Sign UserInfo responses for this client as a JWT (OpenID Connect Core 1.0 "
            "section 5.3.2). Leave blank to return plain JSON."
        ),
        verbose_name=_("UserInfo signing algorithm"),
    )
    token_endpoint_auth_method = models.CharField(
        max_length=32,
        choices=TOKEN_AUTH_METHODS,
        default=TOKEN_AUTH_METHOD_DEFAULT,
        blank=True,
        help_text=_(
            "How the client authenticates to the token endpoint. Leave unset to keep the "
            "legacy behavior (client secret via Basic auth or request body for confidential "
            "clients). When a JWT method is selected the client must authenticate with an "
            "RFC 7523 client assertion and secret-based authentication is rejected."
        ),
        verbose_name=_("token endpoint auth method"),
    )
    client_jwks = models.TextField(
        blank=True,
        default="",
        help_text=_(
            'The client\'s JSON Web Key Set (RFC 7517, {"keys": [...]}) holding the public keys '
            "used to verify private_key_jwt client assertions. Public keys only. "
            "Mutually exclusive with client_jwks_uri."
        ),
        verbose_name=_("client JWKS"),
    )
    client_jwks_uri = models.URLField(
        max_length=500,
        blank=True,
        default="",
        help_text=_(
            "HTTPS URL of the client's JSON Web Key Set, fetched to verify private_key_jwt "
            "client assertions. Mutually exclusive with client_jwks."
        ),
        verbose_name=_("client JWKS URI"),
    )
    # Client metadata the authorization server SHOULD display to the End-User
    # during approval (RFC 7591 section 2, OpenID Connect Dynamic Client
    # Registration 1.0 section 2). clean() requires https, so a value can be
    # placed in an href or src without admitting another scheme.
    client_uri = models.URLField(
        max_length=500,
        blank=True,
        default="",
        help_text=_("HTTPS URL of a web page with information about the client, shown on the consent page."),
        verbose_name=_("client URI"),
    )
    logo_uri = models.URLField(
        max_length=500,
        blank=True,
        default="",
        help_text=_("HTTPS URL of the client's logo image, shown on the consent page."),
        verbose_name=_("logo URI"),
    )
    policy_uri = models.URLField(
        max_length=500,
        blank=True,
        default="",
        help_text=_("HTTPS URL of the client's privacy policy, linked from the consent page."),
        verbose_name=_("policy URI"),
    )
    tos_uri = models.URLField(
        max_length=500,
        blank=True,
        default="",
        help_text=_("HTTPS URL of the client's terms of service, linked from the consent page."),
        verbose_name=_("terms of service URI"),
    )
    # OpenID Connect Dynamic Client Registration 1.0 section 2 request object
    # metadata (OpenID Connect Core 1.0 section 6).
    request_uris = models.TextField(
        blank=True,
        default="",
        help_text=_(
            "HTTPS request_uri values this client may use to pass a request object by reference, "
            "space separated. When any are registered, a request_uri must match one of them "
            "(ignoring the fragment); when none are, any HTTPS request_uri is accepted."
        ),
        verbose_name=_("request URIs"),
    )
    request_object_signing_alg = models.CharField(
        max_length=10,
        blank=True,
        default="",
        help_text=_(
            "The JWS alg every request object from this client must be signed with ('none' for "
            "unsigned). Leave blank to accept any algorithm in OIDC_REQUEST_OBJECT_SIGNING_ALGS. "
            "Signed request objects are verified with client_jwks or client_jwks_uri."
        ),
        verbose_name=_("request object signing alg"),
    )
    allowed_origins = models.TextField(
        blank=True,
        help_text=_("Allowed origins list to enable CORS, space separated"),
        default="",
        verbose_name=_("allowed origins"),
    )
    registration_source = models.CharField(
        max_length=32,
        choices=RegistrationSource.choices,
        default=RegistrationSource.MANUAL,
        help_text=_("How this application was registered (manual, DCR per RFC 7591, or CIMD)"),
        verbose_name=_("registration source"),
    )
    cimd_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text=_("When the cached Client ID Metadata Document should be re-fetched"),
        verbose_name=_("CIMD expires at"),
    )
    # RFC 9126 §6 client metadata. Three-valued: True requires PAR for this client
    # even when the server-wide setting is off; None (the default) defers to the
    # REQUIRE_PUSHED_AUTHORIZATION_REQUESTS setting. The server-wide setting is a
    # floor, so a per-client value never relaxes it (a per-client False therefore
    # only has an effect when the server-wide setting is off, where it matches None).
    require_pushed_authorization_requests = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text=_(
            "Require this client to use Pushed Authorization Requests (RFC 9126). "
            "Leave unset to defer to the REQUIRE_PUSHED_AUTHORIZATION_REQUESTS setting."
        ),
        verbose_name=_("require pushed authorization requests"),
    )
    # An opt-out capability: every application may call the token introspection
    # endpoint unless an operator turns this off (in the admin, or with
    # createapplication --no-can-introspect). RFC 7662 section 4 recommends
    # answering only callers specifically authorized to introspect; deployments
    # that want that turn it off for everything but their resource servers.
    can_introspect = models.BooleanField(
        default=True,
        help_text=_(
            "Allow this client to call the token introspection endpoint (RFC 7662) with an "
            "access token issued to it, or, if it is confidential, by authenticating as itself."
        ),
        verbose_name=_("can introspect tokens"),
    )

    class Meta:
        abstract = True

    def __str__(self):
        return self.name or self.client_id

    @property
    def default_redirect_uri(self):
        """
        Returns the default redirect_uri, *if* only one is registered.
        """
        if self.redirect_uris:
            uris = self.redirect_uris.split()
            if len(uris) == 1:
                return self.redirect_uris.split().pop(0)
            raise errors.MissingRedirectURIError()

        # No redirect_uris registered (e.g. a client_credentials application used
        # in a flow that requires one). Raise an oauthlib error so the endpoint
        # returns a spec-compliant 400 instead of an uncaught AssertionError/500
        # (the assert would also be stripped entirely under `python -O`). See #958.
        raise errors.MissingRedirectURIError()

    def redirect_uri_allowed(self, uri: str) -> bool:
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """
        allowed, reasons = check_redirect_to_uri_allowed(uri, self.redirect_uris.split())
        if not allowed:
            _log_registered_uri_mismatch("redirect_uri", uri, self.client_id, reasons)
        return allowed

    def post_logout_redirect_uri_allowed(self, uri: str) -> bool:
        """
        Checks if given URI is one of the items in :attr:`post_logout_redirect_uris` string

        :param uri: URI to check
        """
        allowed, reasons = check_redirect_to_uri_allowed(uri, self.post_logout_redirect_uris.split())
        if not allowed:
            _log_registered_uri_mismatch("post_logout_redirect_uri", uri, self.client_id, reasons)
        return allowed

    def origin_allowed(self, origin):
        """
        Checks if given origin is one of the items in :attr:`allowed_origins` string

        :param origin: Origin to check
        """
        return self.allowed_origins and is_origin_allowed(origin, self.allowed_origins.split())

    @staticmethod
    def _collect_uri_validation_error(
        field_errors: defaultdict[str, list[ValidationError]],
        field: str,
        exc: ValidationError,
        validated_as: Optional[str] = None,
    ) -> None:
        """Fold a URI validator's ValidationError into the per-field error map.

        The built-in validators always raise a message-and-params error, whose parts are
        reachable as ``error_list``. A validator supplied through REDIRECT_URI_VALIDATOR /
        ALLOWED_ORIGIN_VALIDATOR may instead raise one built from a dict, which has no
        ``error_list`` at all -- reading it would raise ``AttributeError`` out of
        ``clean()``. Honor the dict form by keying each of its messages to the field the
        validator named, which also lets a custom validator report on a field of a swapped
        application model.

        *validated_as* names the field a shared validator was written for, when it was applied
        to *field* instead: a dict-form error keyed to *validated_as* is reported on *field*.
        """
        if hasattr(exc, "error_dict"):
            for error_field, messages in exc.error_dict.items():
                field_errors[field if error_field == validated_as else error_field].extend(messages)
        else:
            field_errors[field].extend(exc.error_list)

    def clean(self) -> None:
        """Validate the application, reporting each problem on the field it belongs to.

        Raises a :class:`~django.core.exceptions.ValidationError` keyed by field name, so
        callers get a per-field ``message_dict`` and a ModelForm renders each message next
        to its input. Every problem found is reported, not just the first one.
        """
        from django.core.exceptions import ValidationError

        grant_types = (
            AbstractApplication.GRANT_AUTHORIZATION_CODE,
            AbstractApplication.GRANT_IMPLICIT,
            AbstractApplication.GRANT_OPENID_HYBRID,
        )
        hs_forbidden_grant_types = (
            AbstractApplication.GRANT_IMPLICIT,
            AbstractApplication.GRANT_OPENID_HYBRID,
        )

        # Errors are keyed by the field they belong to and raised together at the end,
        # rather than raised one at a time as they are found. Keying them means
        # ``full_clean()`` reports them per field (``ValidationError.message_dict``) and a
        # ModelForm -- the admin and the built-in application views both use one -- renders
        # each message next to the offending input instead of as an anonymous non-field
        # error at the top of the form. Collecting them means a single submit reports every
        # problem at once instead of one per round trip.
        field_errors = defaultdict(list)

        redirect_uris = self.redirect_uris.strip().split()
        # Post-logout redirect URIs are redirect targets too (OpenID Connect RP-Initiated
        # Logout 1.0 section 3.1), so they get the same validator. Split before validating,
        # as for redirect_uris, so every URI that post_logout_redirect_uri_allowed() can
        # match is one that was validated.
        post_logout_redirect_uris = self.post_logout_redirect_uris.strip().split()
        if redirect_uris or post_logout_redirect_uris:
            # Built once for both fields, so a database-backed factory queries once per save.
            redirect_uri_validator = self.get_redirect_uri_validator()

        if redirect_uris:
            for uri in redirect_uris:
                try:
                    redirect_uri_validator(uri)
                except ValidationError as exc:
                    self._collect_uri_validation_error(field_errors, "redirect_uris", exc)

        elif self.authorization_grant_type in grant_types:
            field_errors["redirect_uris"].append(
                ValidationError(
                    _("redirect_uris cannot be empty with grant_type {grant_type}").format(
                        grant_type=self.authorization_grant_type
                    )
                )
            )
        allowed_origins = self.allowed_origins.strip().split()
        if allowed_origins:
            allowed_origin_validator = self.get_allowed_origin_validator()
            for uri in allowed_origins:
                try:
                    allowed_origin_validator(uri)
                except ValidationError as exc:
                    self._collect_uri_validation_error(field_errors, "allowed_origins", exc)

        # In strict mode RP-Initiated Logout never redirects a client that is not confidential
        # to an http URI (see validate_post_logout_redirect_uri()), so refuse to store one.
        strict_post_logout = (
            oauth2_settings.OIDC_ENABLED
            and oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED
            and oauth2_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS
            and self.client_type != AbstractApplication.CLIENT_CONFIDENTIAL
        )
        for uri in post_logout_redirect_uris:
            try:
                redirect_uri_validator(uri)
            except ValidationError as exc:
                # The validator is shared with redirect_uris, so an error it keys to that field
                # is about the post-logout URI it was given.
                self._collect_uri_validation_error(
                    field_errors, "post_logout_redirect_uris", exc, validated_as="redirect_uris"
                )
                continue
            # A custom validator may accept a URI urlsplit() cannot parse; leave that one be.
            with suppress(ValueError):
                if strict_post_logout and urlsplit(uri).scheme == "http":
                    field_errors["post_logout_redirect_uris"].append(
                        ValidationError(
                            _("http is only allowed with confidential clients: %(value)s"),
                            params={"value": uri},
                        )
                    )

        for field in ("client_uri", "logo_uri", "policy_uri", "tos_uri"):
            value = getattr(self, field)
            if value and not value.lower().startswith("https://"):
                field_errors[field].append(
                    ValidationError(_("{field} must use the https scheme.").format(field=field))
                )

        if self.algorithm == AbstractApplication.RS256_ALGORITHM:
            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                field_errors["algorithm"].append(
                    ValidationError(_("You must set OIDC_RSA_PRIVATE_KEY to use RSA algorithm"))
                )

        if self.userinfo_signed_response_alg == AbstractApplication.RS256_ALGORITHM:
            # Imported here so that loading the models does not import the authorization
            # server package.
            from oauth2_provider.authorization_server.oidc.server import userinfo_signing_available

            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                field_errors["userinfo_signed_response_alg"].append(
                    ValidationError(
                        _("You must set OIDC_RSA_PRIVATE_KEY to sign UserInfo responses with RSA")
                    )
                )
            elif not userinfo_signing_available():
                field_errors["userinfo_signed_response_alg"].append(
                    ValidationError(
                        _(
                            "This server cannot sign UserInfo responses: it needs OIDC_ENABLED, an "
                            "importable OIDC_SERVER_CLASS (or OAUTH2_SERVER_CLASS) derived from "
                            "oauth2_provider.authorization_server.oidc.server.Server, and an "
                            "importable OAUTH2_VALIDATOR_CLASS with a callable finalize_userinfo_response, "
                            "as OAuth2Validator has."
                        )
                    )
                )
            elif self.algorithm == AbstractApplication.NO_ALGORITHM:
                # The signed response is an OpenID Connect artefact like the ID Token, and an
                # application without OIDC support has no key to verify tokens naming it.
                field_errors["userinfo_signed_response_alg"].append(
                    ValidationError(
                        _("You cannot sign UserInfo responses for an application without OIDC support")
                    )
                )

        if self.algorithm == AbstractApplication.HS256_ALGORITHM:
            if any(
                (
                    self.authorization_grant_type in hs_forbidden_grant_types,
                    self.client_type == Application.CLIENT_PUBLIC,
                )
            ):
                field_errors["algorithm"].append(
                    ValidationError(_("You cannot use HS256 with public grants or clients"))
                )
            if not self.client_secret:
                field_errors["client_secret"].append(
                    ValidationError(
                        _("You cannot use HS256 without a client secret; it is the HMAC signing key.")
                    )
                )
            # For HS256 the client secret is the shared HMAC signing key, so it must be stored
            # unhashed. Reject both the intent to hash (the flag) and an already-hashed stored
            # value (e.g. the flag was toggled after the secret was hashed, or a legacy row), so
            # the misconfiguration surfaces here instead of only failing later at signing time.
            # The error goes on whichever field has to change: the flag when it is still set,
            # otherwise the already-hashed secret itself, which has to be re-entered unhashed.
            elif self.hash_client_secret or self._client_secret_is_hashed(self.client_secret):
                field_errors["hash_client_secret" if self.hash_client_secret else "client_secret"].append(
                    ValidationError(
                        _(
                            "You cannot use HS256 with a hashed client secret. For HS256 the client "
                            "secret is the shared signing key and must be stored unhashed so the relying "
                            "party can verify the token; set hash_client_secret=False and store an "
                            "unhashed client_secret on this application."
                        )
                    )
                )

        self._clean_client_assertion_config(field_errors)
        self._clean_request_object_config(field_errors)

        if field_errors:
            raise ValidationError(field_errors)

    def _clean_client_assertion_config(self, field_errors):
        """Validate the RFC 7523 client authentication fields (see clean()).

        Errors are appended to *field_errors* keyed by the field that has to
        change, following the same convention as the rest of ``clean()``.
        """
        if self.client_jwks and self.client_jwks_uri:
            field_errors["client_jwks"].append(
                ValidationError(_("client_jwks and client_jwks_uri are mutually exclusive."))
            )
        if self.client_jwks:
            key_set = None
            try:
                key_set = jwk.JWKSet.from_json(self.client_jwks)
            except (ValueError, JWException) as exc:
                field_errors["client_jwks"].append(
                    ValidationError(_("client_jwks is not a valid JWK Set: {err}").format(err=exc))
                )
            if key_set is not None:
                if not key_set["keys"]:
                    field_errors["client_jwks"].append(
                        ValidationError(_("client_jwks must contain at least one key."))
                    )
                # The AS only ever needs the public halves; storing a private key
                # here would put a client credential server-side by accident.
                elif any(key.has_private for key in key_set["keys"]):
                    field_errors["client_jwks"].append(
                        ValidationError(_("client_jwks must contain public keys only, never private keys."))
                    )
                # An oct key is a shared symmetric secret: private_key_jwt never
                # uses one, and anyone who can read the key set could sign with it.
                elif any(key.get("kty") == "oct" for key in key_set["keys"]):
                    field_errors["client_jwks"].append(
                        ValidationError(
                            _(
                                "client_jwks must contain asymmetric public keys only; "
                                "an oct key is a shared secret."
                            )
                        )
                    )
                # A key set that permits no signature verification (e.g. use=enc
                # everywhere, or key_ops without "verify") can never authenticate
                # this client; fail at registration instead of at the first login.
                elif not any(jwk_allows_verification(key) for key in key_set["keys"]):
                    field_errors["client_jwks"].append(
                        ValidationError(
                            _(
                                "client_jwks must contain at least one key usable for signature "
                                'verification (use "sig", or key_ops including "verify").'
                            )
                        )
                    )
        if self.client_jwks_uri and not self.client_jwks_uri.lower().startswith("https://"):
            field_errors["client_jwks_uri"].append(
                ValidationError(_("client_jwks_uri must use the https scheme."))
            )

        method = self.token_endpoint_auth_method
        if method == AbstractApplication.TOKEN_AUTH_METHOD_NONE:
            if self.client_type == AbstractApplication.CLIENT_CONFIDENTIAL:
                field_errors["token_endpoint_auth_method"].append(
                    ValidationError(_("A confidential client cannot use token_endpoint_auth_method 'none'."))
                )
        if method in AbstractApplication.JWT_AUTH_METHODS:
            if self.client_type != AbstractApplication.CLIENT_CONFIDENTIAL:
                field_errors["token_endpoint_auth_method"].append(
                    ValidationError(
                        _("token_endpoint_auth_method {method} requires a confidential client.").format(
                            method=method
                        )
                    )
                )
        if method == AbstractApplication.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT:
            if not (self.client_jwks or self.client_jwks_uri):
                field_errors["client_jwks"].append(
                    ValidationError(_("private_key_jwt requires client_jwks or client_jwks_uri to be set."))
                )
        if method == AbstractApplication.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT:
            if not self.client_secret:
                field_errors["client_secret"].append(
                    ValidationError(
                        _("client_secret_jwt requires a client secret; it is the HMAC signing key.")
                    )
                )
            # Same constraint as HS256 id_token signing above: the secret is the
            # shared HMAC key, so a hashed copy can never verify anything. The
            # error goes on whichever field has to change.
            elif self.hash_client_secret or self._client_secret_is_hashed(self.client_secret):
                field_errors["hash_client_secret" if self.hash_client_secret else "client_secret"].append(
                    ValidationError(
                        _(
                            "client_secret_jwt requires the plaintext client secret as the HMAC key. "
                            "Set hash_client_secret=False and store an unhashed client_secret on "
                            "this application."
                        )
                    )
                )

    def _clean_request_object_config(self, field_errors: dict[str, list]) -> None:
        """Validate the request object fields (see clean()).

        OpenID Connect Dynamic Client Registration 1.0 section 2 requires
        ``request_uris`` to use the https scheme. A signed
        ``request_object_signing_alg`` is verified against the client's
        registered keys, so it needs ``client_jwks`` or ``client_jwks_uri``.

        The ``request_object_signing_alg`` checks only apply while request
        objects are enabled. Otherwise the stored value is unused, and Dynamic
        Client Registration and CIMD leave it as it is, so checking it would
        refuse every update of a client that registered it (say, one dropping
        its keys) for a value the client cannot change. Should request objects
        be enabled again, a signing alg without keys fails closed.
        """
        from django.core.exceptions import ValidationError

        from oauth2_provider.authorization_server.oidc.request_objects import request_objects_enabled

        for uri in self.request_uris.split():
            if not uri.lower().startswith("https://"):
                field_errors["request_uris"].append(
                    ValidationError(_("request_uris must use the https scheme: {uri}").format(uri=uri))
                )
        alg = self.request_object_signing_alg
        if not alg or not request_objects_enabled():
            return
        if alg not in oauth2_settings.OIDC_REQUEST_OBJECT_SIGNING_ALGS:
            field_errors["request_object_signing_alg"].append(
                ValidationError(
                    _("request_object_signing_alg {alg} is not in OIDC_REQUEST_OBJECT_SIGNING_ALGS.").format(
                        alg=alg
                    )
                )
            )
        elif alg != "none" and not (self.client_jwks or self.client_jwks_uri):
            field_errors["request_object_signing_alg"].append(
                ValidationError(
                    _(
                        "request_object_signing_alg {alg} requires client_jwks or client_jwks_uri "
                        "to verify the request object signature."
                    ).format(alg=alg)
                )
            )

    def get_absolute_url(self):
        return reverse("oauth2_provider:detail", args=[str(self.pk)])

    def get_allowed_schemes(self):
        """
        Returns the list of redirect schemes allowed by the Application.
        By default, returns `ALLOWED_REDIRECT_URI_SCHEMES`.
        """
        return oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES

    def get_redirect_uri_validator(self) -> Callable[[str], None]:
        """
        Returns the validator ``clean()`` applies to each entry in ``redirect_uris`` and
        ``post_logout_redirect_uris``. By default, builds one from the `REDIRECT_URI_VALIDATOR`
        setting.

        The setting names a factory called with this application; the object it returns is
        called once per URI and raises ``ValidationError`` for anything unacceptable.
        Because the factory runs once per ``clean()`` rather than once per URI, a policy
        backed by the database queries once per save. Note this application may be unsaved
        (``pk is None``) when registration goes through Dynamic Client Registration, CIMD
        or the admin add form, so an override must not assume reverse relations exist.

        This gates what may be *stored*. At request time a redirect uri is still matched by
        exact string comparison (see ``check_redirect_to_uri_allowed()``), and the scheme is
        separately gated by ``get_allowed_schemes()``, which no validator here can relax.
        """
        return oauth2_settings.REDIRECT_URI_VALIDATOR(self)

    def get_allowed_origin_validator(self) -> Callable[[str], None]:
        """
        Returns the validator ``clean()`` applies to each entry in ``allowed_origins``.
        By default, builds one from the `ALLOWED_ORIGIN_VALIDATOR` setting.

        Follows the same factory contract as ``get_redirect_uri_validator()``. An origin
        whose scheme is outside ``ALLOWED_SCHEMES`` is still rejected at request time by
        ``is_origin_allowed()`` even if a custom validator lets it be stored.
        """
        return oauth2_settings.ALLOWED_ORIGIN_VALIDATOR(self)

    def allows_grant_type(self, *grant_types):
        return self.authorization_grant_type in grant_types

    def is_usable(self, request):
        """
        Determines whether the application can be used.

        :param request: The oauthlib.common.Request being processed.
        """
        return True

    @staticmethod
    def _client_secret_is_hashed(client_secret):
        """Return True if the stored client secret is a Django password hash."""
        try:
            identify_hasher(client_secret)
        except ValueError:
            return False
        return True

    @property
    def jwk_key(self):
        if self.algorithm == AbstractApplication.RS256_ALGORITHM:
            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                raise ImproperlyConfigured("You must set OIDC_RSA_PRIVATE_KEY to use RSA algorithm")
            return jwk_from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY)
        elif self.algorithm == AbstractApplication.HS256_ALGORITHM:
            # An empty secret would sign tokens with an empty HMAC key, which is trivially
            # forgeable by anyone.
            if not self.client_secret:
                raise ImproperlyConfigured(
                    "HS256 signing requires a non-empty client secret to use as the HMAC key."
                )
            # A hashed secret would sign tokens with the password hash string as the HMAC key,
            # which the relying party (holding the plaintext secret) can never verify.
            if self._client_secret_is_hashed(self.client_secret):
                raise ImproperlyConfigured(
                    "HS256 signing requires the plaintext client secret as the HMAC key, but this "
                    "application's client secret is hashed. Set hash_client_secret=False and reset "
                    "the client_secret (or recreate the application) so the plaintext secret is stored."
                )
            return jwk.JWK(kty="oct", k=base64url_encode(self.client_secret))
        raise ImproperlyConfigured("This application does not support signed tokens")

    def get_client_signing_jwks(self):
        """Return the inline ``jwk.JWKSet`` used to verify this client's RFC 7523
        assertions, or None when no inline JWKS is registered.

        Remote ``client_jwks_uri`` resolution deliberately lives in
        :mod:`oauth2_provider.authorization_server.client_assertions` so the model stays network-free.
        """
        if not self.client_jwks:
            return None
        return jwk.JWKSet.from_json(self.client_jwks)

    def get_client_secret_hmac_jwk(self):
        """Return the ``oct`` JWK derived from the plaintext client secret, used to
        verify client_secret_jwt assertions (RFC 7523 section 2.2).

        Distinct from :attr:`jwk_key`, which is the key the *server* signs
        ID tokens with; this one verifies what the *client* signed.
        """
        # An empty or hashed secret can never verify an HMAC the client computed
        # over the plaintext secret; fail loudly instead of silently rejecting.
        # The hash_client_secret flag is checked too (mirroring clean()) so a
        # row that slipped past model validation still fails closed here.
        if not self.client_secret:
            raise ImproperlyConfigured(
                "client_secret_jwt requires a non-empty client secret to use as the HMAC key."
            )
        if self.hash_client_secret or self._client_secret_is_hashed(self.client_secret):
            raise ImproperlyConfigured(
                "client_secret_jwt requires the plaintext client secret as the HMAC key, but this "
                "application hashes its client secret. Set hash_client_secret=False and reset the "
                "client_secret so the plaintext secret is stored."
            )
        return jwk.JWK(kty="oct", k=base64url_encode(self.client_secret))


class ApplicationManager(models.Manager):
    def get_by_natural_key(self, client_id):
        return self.get(client_id=client_id)


class Application(AbstractApplication):
    objects = ApplicationManager()

    class Meta(AbstractApplication.Meta):
        swappable = "OAUTH2_PROVIDER_APPLICATION_MODEL"

    def natural_key(self):
        return (self.client_id,)


class AbstractGrant(models.Model):
    """
    A Grant instance represents a token with a short lifetime that can
    be swapped for an access token, as described in :rfc:`4.1.2`

    Fields:

    * :attr:`user` The Django user who requested the grant
    * :attr:`code` The authorization code generated by the authorization server
    * :attr:`application` Application instance this grant was asked for
    * :attr:`expires` Expire time in seconds, defaults to
                      :data:`settings.AUTHORIZATION_CODE_EXPIRE_SECONDS`
    * :attr:`redirect_uri` Self explained
    * :attr:`scope` Required scopes, optional
    * :attr:`code_challenge` PKCE code challenge
    * :attr:`code_challenge_method` PKCE code challenge transform algorithm
    * :attr:`resource` RFC 8707 resource indicator(s), JSON-encoded array of URIs
    """

    CODE_CHALLENGE_PLAIN = "plain"
    CODE_CHALLENGE_S256 = "S256"
    CODE_CHALLENGE_METHODS = ((CODE_CHALLENGE_PLAIN, "plain"), (CODE_CHALLENGE_S256, "S256"))

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    code = models.CharField(max_length=255, unique=True, verbose_name=_("code"))  # code comes from oauthlib
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE, verbose_name=_("application")
    )
    expires = models.DateTimeField(verbose_name=_("expires"))
    redirect_uri = models.TextField(verbose_name=_("redirect URI"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))

    code_challenge = models.CharField(
        max_length=128, blank=True, default="", verbose_name=_("code challenge")
    )
    code_challenge_method = models.CharField(
        max_length=10,
        blank=True,
        default="",
        choices=CODE_CHALLENGE_METHODS,
        verbose_name=_("code challenge method"),
    )

    nonce = models.CharField(max_length=255, blank=True, default="", verbose_name=_("nonce"))
    # The Authentication Context Class Reference the End-User's authentication
    # satisfied (OpenID Connect Core 1.0 section 2), determined at the
    # authorization endpoint for the ID Token issued at code exchange.
    acr = models.CharField(
        max_length=255, blank=True, default="", verbose_name=_("authentication context class reference")
    )
    claims = models.TextField(blank=True, verbose_name=_("claims"))

    resource = ResourceJSONField(blank=True, default=list, verbose_name=_("resource"))

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri: str) -> bool:
        allowed = uri == self.redirect_uri
        if not allowed and logger.isEnabledFor(logging.DEBUG):
            # Never log self.code alongside this: an authorization code in a log
            # file is a credential, which is why __str__ below omits it too.
            logger.debug(
                "redirect_uri %s does not match the redirect_uri %s recorded on grant #%s at "
                "authorization time; RFC 6749 section 4.1.3 requires them to be identical",
                _loggable_uri(uri),
                _loggable_uri(self.redirect_uri),
                self.pk,
            )
        return allowed

    def __str__(self):
        # Never render the authorization code itself: __str__ appears in the admin
        # change page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "Grant #{self.pk}".format(self=self)

    class Meta:
        abstract = True


class Grant(AbstractGrant):
    class Meta(AbstractGrant.Meta):
        swappable = "OAUTH2_PROVIDER_GRANT_MODEL"


class AbstractAccessToken(models.Model):
    """
    An AccessToken instance represents the actual access token to
    access user's resources, as in :rfc:`5`.

    Fields:

    * :attr:`user` The Django user representing resources" owner
    * :attr:`source_refresh_token` If from a refresh, the consumed RefeshToken
    * :attr:`token` Access token
    * :attr:`application` Application instance
    * :attr:`expires` Date and time of token expiration, in DateTime format
    * :attr:`scope` Allowed scopes
    * :attr:`resource` RFC 8707 resource indicator(s) - JSON-encoded array of URIs
    * :attr:`claims` The OIDC ``claims`` request (Core 5.5) the token was issued for
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    source_refresh_token = models.OneToOneField(
        # unique=True implied by the OneToOneField
        oauth2_settings.REFRESH_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refreshed_access_token",
        verbose_name=_("source refresh token"),
    )
    token = models.TextField(verbose_name=_("token"))
    token_checksum = TokenChecksumField(
        max_length=64,
        blank=False,
        unique=True,
        db_index=True,
        verbose_name=_("token checksum"),
    )
    id_token = models.OneToOneField(
        oauth2_settings.ID_TOKEN_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="access_token",
        verbose_name=_("ID token"),
    )
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_("application"),
    )

    expires = models.DateTimeField(verbose_name=_("expires"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))

    resource = ResourceJSONField(blank=True, default=list, verbose_name=_("resource"))
    # The normalized OIDC claims request (Core 5.5) behind this token, so the UserInfo
    # endpoint and a refresh know which individual claims were requested.
    claims = ClaimsRequestJSONField(blank=True, default=dict, verbose_name=_("claims"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def allows_audience(self, audience_uri):
        """
        Check if the token is authorized for the given audience URI.

        RFC 8707: Validates that the token includes the specified resource indicator
        using the configured resource validator (RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR).

        If the token has no resource indicators (empty list), it is unrestricted and
        allows any audience (backward compatibility).

        :param audience_uri: The URI of the resource server to check
        :return: True if the token is authorized for this audience, False otherwise
        """
        audiences = self.resource
        if not audiences:
            # No resource indicators - unrestricted token allows any audience,
            # regardless of how a custom validator treats an empty list.
            return True

        resource_validator = oauth2_settings.RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR

        if resource_validator:
            return resource_validator(audience_uri, audiences)
        else:
            # No validator configured - allow everything (backward compat)
            return True

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Convenience method to uniform tokens" interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    @property
    def scopes(self):
        """
        Returns a dictionary of allowed scope names (as keys) with their descriptions (as values)
        """
        all_scopes = get_scopes_backend().get_all_scopes()
        token_scopes = self.scope.split()
        return {name: desc for name, desc in all_scopes.items() if name in token_scopes}

    def __str__(self):
        # Never render the token itself: __str__ appears in the admin change
        # page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "AccessToken #{self.pk}".format(self=self)

    class Meta:
        abstract = True


class AccessToken(AbstractAccessToken):
    class Meta(AbstractAccessToken.Meta):
        swappable = "OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL"


class AbstractRefreshToken(models.Model):
    """
    A RefreshToken instance represents a token that can be swapped for a new
    access token when it expires.

    Fields:

    * :attr:`user` The Django user representing resources" owner
    * :attr:`token` Token value
    * :attr:`application` Application instance
    * :attr:`access_token` AccessToken instance this refresh token is
                           bounded to
    * :attr:`revoked` Timestamp of when this refresh token was revoked
    * :attr:`resource` RFC 8707 resource indicator(s), JSON-encoded array of URIs
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    token = models.TextField(verbose_name=_("token"))
    # Unique across every row, live or revoked -- not scoped to the live ones. A refresh
    # token value is a bearer credential and is the sole lookup key
    # (``validate_refresh_token``), so two rows sharing one value leave nothing to say
    # which row a presented token means. Rotation always mints a fresh value, and a
    # non-rotating refresh leaves the existing row in place instead of inserting a second
    # one, so a collision here points at a broken REFRESH_TOKEN_GENERATOR.
    token_checksum = TokenChecksumField(
        max_length=64,
        blank=False,
        unique=True,
        db_index=True,
        verbose_name=_("token checksum"),
    )
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE, verbose_name=_("application")
    )
    access_token = models.OneToOneField(
        oauth2_settings.ACCESS_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refresh_token",
        verbose_name=_("access token"),
    )
    token_family = models.UUIDField(null=True, blank=True, editable=False, verbose_name=_("token family"))

    resource = ResourceJSONField(blank=True, default=list, verbose_name=_("resource"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))
    revoked = models.DateTimeField(null=True, verbose_name=_("revoked"))

    @classmethod
    def revoke_family(cls, token_family: uuid.UUID | None) -> None:
        """
        Revoke every live refresh token sharing ``token_family`` and delete the family's
        access tokens, in a constant number of queries.

        This is the set-based equivalent of calling :meth:`revoke` on each member of the
        family, which is what reuse protection needs: a rotating client adds a row to its
        family on every refresh, so revoking row by row cost one ``SELECT ... FOR UPDATE``
        round trip per token ever issued to that session, paid again on every replay of the
        stale token (#1809). A model that overrides :meth:`revoke` to do more should
        override this too.

        Rows are not locked up front: unlike rotation this path mints nothing, so there is
        no read-then-write to protect. The statements take their locks in the same order as
        :meth:`revoke` -- refresh token, then access token -- so a concurrent rotation in
        the family cannot deadlock against the sweep.

        One ``timezone.now()`` is stamped across the whole family. That is safe because
        ``token_checksum`` is unique on its own: two live members cannot share a checksum,
        so the shared timestamp has no uniqueness to collide with (#1816).
        """
        if not token_family:
            return

        access_token_model = get_access_token_model()
        access_token_database = router.db_for_write(access_token_model)

        with transaction.atomic(using=access_token_database):
            now = timezone.now()
            # ``updated`` is ``auto_now``, which a queryset update does not trigger.
            cls.objects.filter(token_family=token_family, revoked__isnull=True).update(
                revoked=now, updated=now
            )
            # Deleting is what ``AccessToken.revoke()`` does, and ``access_token`` is
            # ``SET_NULL``, so this clears the pointer on the rows revoked above as well.
            # The family is re-read rather than snapshotted before the update, so a member
            # rotated in concurrently loses its access token too and is left an orphan,
            # which ``validate_refresh_token`` rejects. Sub-selecting through the forward
            # FK avoids the reverse accessor, whose name a swapped model may change.
            access_token_model.objects.filter(
                pk__in=cls.objects.filter(token_family=token_family).values("access_token_id")
            ).delete()

    def revoke(self):
        """
        Mark this refresh token revoked and revoke related access token
        """
        access_token_model = get_access_token_model()
        access_token_database = router.db_for_write(access_token_model)
        refresh_token_model = get_refresh_token_model()

        # Use the access_token_database instead of making the assumption it is in 'default'.
        with transaction.atomic(using=access_token_database):
            token = refresh_token_model.objects.select_for_update().filter(pk=self.pk, revoked__isnull=True)
            if not token:
                return
            self = list(token)[0]

            with suppress(access_token_model.DoesNotExist):
                access_token_model.objects.get(pk=self.access_token_id).revoke()

            self.access_token = None
            self.revoked = timezone.now()
            self.save()

    def __str__(self):
        # Never render the token itself: __str__ appears in the admin change
        # page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "RefreshToken #{self.pk}".format(self=self)

    class Meta:
        abstract = True
        indexes = [
            # ``revoke_family()`` filters on ``token_family`` on the ``/token/`` path,
            # and without an index that is a scan of the whole refresh token table.
            models.Index(fields=["token_family"]),
        ]


class RefreshToken(AbstractRefreshToken):
    class Meta(AbstractRefreshToken.Meta):
        swappable = "OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL"


class RevokedTokenEvidence(models.Model):
    """Non-credential evidence that a refresh token was revoked.

    A revoked refresh token has to exist as a row for
    ``REFRESH_TOKEN_REUSE_PROTECTION`` to recognize a replay and revoke the family it
    belongs to. A deleted account carries all of its refresh token rows away with it
    (``RefreshToken.user`` is ``CASCADE``), so :func:`purge_user_credentials` copies the
    minimum needed to keep that judgment possible into this table first -- only when an
    explicit ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` policy asks for it.

    What is stored is deliberately not a credential:

    * ``token_checksum`` is the SHA-256 of the token value. It recognizes a replay but,
      for a high-entropy token, cannot be reversed into a usable token.
    * ``token_family`` and ``client_id`` are identifiers the reuse sweep needs. Neither is
      secret.
    * ``revoked_at`` and ``retain_until`` say when the evidence stops being needed.
      ``retain_until`` is ``NULL`` when the evidence must be kept indefinitely (reuse
      protection on, refresh tokens never age-expire, and no explicit retention policy).

    There is no user reference, no raw token value, no scope, and no foreign key to the
    application (the application may itself be deleted with the account). The row cannot
    be exchanged for an access token and does not make anything usable; it only outlives
    the credential it describes. ``clear_expired`` prunes rows past ``retain_until`` on
    the same schedule as the other expired data.
    """

    id = models.BigAutoField(primary_key=True)
    token_checksum = models.CharField(
        max_length=64, unique=True, db_index=True, verbose_name=_("token checksum")
    )
    token_family = models.UUIDField(null=True, blank=True, verbose_name=_("token family"))
    client_id = models.CharField(max_length=255, blank=True, default="", verbose_name=_("client ID"))
    revoked_at = models.DateTimeField(verbose_name=_("revoked at"))
    # Indexed because ``clear_expired`` prunes by this column on every run. ``NULL`` means
    # "retain indefinitely" and is never matched by the prune query.
    retain_until = models.DateTimeField(null=True, blank=True, db_index=True, verbose_name=_("retain until"))
    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))

    def __str__(self):
        # Never render the checksum: __str__ appears in the admin, repr() in tracebacks,
        # and in log output.
        return "RevokedTokenEvidence #{self.pk}".format(self=self)

    class Meta:
        verbose_name = _("revoked token evidence")
        verbose_name_plural = _("revoked token evidence")


class TokenCleanupRun(models.Model):
    """Bookkeeping for one :func:`clear_expired` invocation.

    ``clear_expired`` deletes in phases and in bounded batches, so an operator can stop it
    (deploy, timeout, Ctrl-C) and run it again later. This row is what makes that
    *resumable* rather than merely retryable: it records which phases already finished,
    which phase was running, and the counts accumulated so far. A restart with
    ``resume=True`` continues from the interrupted phase; every phase is idempotent, so
    even a run that starts over from phase one reaches the same state.

    The row holds no credential material -- only phase names, counts and timestamps -- so
    it is safe to inspect in the admin or expose through monitoring.
    """

    RUNNING = "running"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"
    FAILED = "failed"
    STATUS_CHOICES = (
        (RUNNING, _("Running")),
        (INTERRUPTED, _("Interrupted")),
        (COMPLETED, _("Completed")),
        (FAILED, _("Failed")),
    )

    id = models.BigAutoField(primary_key=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=RUNNING, db_index=True)
    # The phase that was running when the row was last written; for a completed run, the
    # last phase. Kept as a name, not an index, so reordering PHASES cannot silently
    # resume at the wrong point.
    phase = models.CharField(max_length=32, blank=True, default="")
    completed_phases = models.JSONField(default=list, blank=True)
    counts = models.JSONField(default=dict, blank=True)
    batches = models.PositiveIntegerField(default=0)
    cutoffs = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "TokenCleanupRun #{self.pk}".format(self=self)

    class Meta:
        verbose_name = _("token cleanup run")
        verbose_name_plural = _("token cleanup runs")
        indexes = [
            # ``clear_expired(resume=True)`` finds the latest unfinished run by status.
            models.Index(fields=["status", "-id"]),
        ]


class AbstractIDToken(models.Model):
    """
    An IDToken instance represents the token used to authenticate the user and
    convey claims to the client, as in
    `OpenID Connect Core 1.0 Section 2 <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_.

    Fields:

    * :attr:`user` The Django user representing resources' owner
    * :attr:`jti` ID token JWT Token ID, to identify an individual token
    * :attr:`application` Application instance
    * :attr:`expires` Date and time of token expiration, in DateTime format
    * :attr:`scope` Allowed scopes
    * :attr:`created` Date and time of token creation, in DateTime format
    * :attr:`updated` Date and time of token update, in DateTime format
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    jti = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, verbose_name=_("JWT Token ID"))
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_("application"),
    )
    expires = models.DateTimeField(verbose_name=_("expires"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Convenience method to uniform tokens' interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    @property
    def scopes(self):
        """
        Returns a dictionary of allowed scope names (as keys) with their descriptions (as values)
        """
        all_scopes = get_scopes_backend().get_all_scopes()
        token_scopes = self.scope.split()
        return {name: desc for name, desc in all_scopes.items() if name in token_scopes}

    def __str__(self):
        return "JTI: {self.jti} User: {self.user_id}".format(self=self)

    class Meta:
        abstract = True


class IDToken(AbstractIDToken):
    class Meta(AbstractIDToken.Meta):
        swappable = "OAUTH2_PROVIDER_ID_TOKEN_MODEL"


class AbstractDeviceGrant(models.Model):
    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(
                fields=["device_code"],
                name="%(app_label)s_%(class)s_unique_device_code",
            ),
        ]

    AUTHORIZED = "authorized"
    AUTHORIZATION_PENDING = "authorization-pending"
    EXPIRED = "expired"
    DENIED = "denied"

    DEVICE_FLOW_STATUS = (
        (AUTHORIZED, _("Authorized")),
        (AUTHORIZATION_PENDING, _("Authorization pending")),
        (EXPIRED, _("Expired")),
        (DENIED, _("Denied")),
    )

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="%(app_label)s_%(class)s",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        verbose_name=_("user"),
    )
    # Uniqueness is enforced by the unique_device_code UniqueConstraint (Meta.constraints);
    # adding unique=True here would create a redundant duplicate index (MySQL warns ER_DUP_INDEX 1831).
    device_code = models.CharField(max_length=100, verbose_name=_("device code"))
    user_code = models.CharField(max_length=100, verbose_name=_("user code"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))
    interval = models.IntegerField(default=5, verbose_name=_("interval"))
    expires = models.DateTimeField(verbose_name=_("expires"))
    status = models.CharField(
        max_length=64,
        blank=True,
        choices=DEVICE_FLOW_STATUS,
        default=AUTHORIZATION_PENDING,
        verbose_name=_("status"),
    )
    client_id = models.CharField(max_length=100, db_index=True, verbose_name=_("client ID"))
    last_checked = models.DateTimeField(auto_now=True, verbose_name=_("last checked"))

    def is_expired(self):
        """
        Check device flow session expiration and set the status to "expired" if current time
        is past the "expires" deadline.
        """
        if self.status == self.EXPIRED:
            return True

        now = datetime.now(tz=dt_timezone.utc)
        if now >= self.expires:
            self.status = self.EXPIRED
            self.save(update_fields=["status"])
            return True

        return False


class DeviceGrant(AbstractDeviceGrant):
    class Meta(AbstractDeviceGrant.Meta):
        swappable = "OAUTH2_PROVIDER_DEVICE_GRANT_MODEL"


@dataclass
class DeviceRequest:
    # https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
    # scope is optional
    client_id: str
    scope: Optional[str] = None


@dataclass
class DeviceCodeResponse:
    verification_uri: str
    expires_in: int
    user_code: str
    device_code: str
    interval: int
    verification_uri_complete: Optional[Union[str, Callable]] = None


def create_device_grant(
    device_request: DeviceRequest, device_response: DeviceCodeResponse
) -> AbstractDeviceGrant:
    now = datetime.now(tz=dt_timezone.utc)

    return get_device_grant_model().objects.create(
        client_id=device_request.client_id,
        device_code=device_response.device_code,
        user_code=device_response.user_code,
        scope=device_request.scope or "",
        expires=now + timedelta(seconds=device_response.expires_in),
    )


class AbstractStoredAuthorizationRequest(models.Model):
    """
    A validated authorization request kept by the authorization server.

    The request is referenced by a single-use, client-bound ``request_uri`` in
    the ``urn:ietf:params:oauth:request_uri:`` namespace (:rfc:`9126#section-2.2`),
    so the authorization endpoint can be called with only ``client_id`` and
    ``request_uri`` instead of the full parameter set. Requests pushed to the
    pushed authorization request endpoint (:rfc:`9126`) are stored here, and so
    is a request carried across a login. Only requests that have already been
    validated in full are stored; see
    :mod:`oauth2_provider.authorization_server.stored_requests`.

    Fields:

    * :attr:`request_uri` The single-use ``urn:ietf:params:oauth:request_uri:*``
                          reference given to the client.
    * :attr:`client_id` The client the request URI is bound to (:rfc:`9126#section-2.2`).
    * :attr:`parameters` The authorization-request parameters, stored as a JSON
                         mapping (client-authentication parameters excluded).
    * :attr:`expires` When the request URI ceases to be valid.
    """

    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(
                fields=["request_uri"],
                name="%(app_label)s_%(class)s_unique_request_uri",
            ),
        ]

    id = models.BigAutoField(primary_key=True)
    # Uniqueness is enforced by the unique_request_uri UniqueConstraint
    # (Meta.constraints); adding unique=True here would create a redundant
    # duplicate index (MySQL warns ER_DUP_INDEX 1831).
    request_uri = models.CharField(max_length=255, verbose_name=_("request URI"))
    client_id = models.CharField(max_length=100, db_index=True, verbose_name=_("client id"))
    parameters = models.JSONField(default=dict, verbose_name=_("parameters"))
    expires = models.DateTimeField(verbose_name=_("expires"))
    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))

    def is_expired(self) -> bool:
        """Whether the request URI has passed its ``expires`` deadline."""
        if not self.expires:
            return True
        return timezone.now() >= self.expires

    def __str__(self) -> str:
        # Never render the request_uri itself: __str__ appears in the admin
        # change page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "StoredAuthorizationRequest #{self.pk}".format(self=self)


class StoredAuthorizationRequest(AbstractStoredAuthorizationRequest):
    class Meta(AbstractStoredAuthorizationRequest.Meta):
        swappable = "OAUTH2_PROVIDER_STORED_AUTHORIZATION_REQUEST_MODEL"


def create_stored_authorization_request(
    request_uri: str, client_id: str, parameters: dict, expires_in: int
) -> AbstractStoredAuthorizationRequest:
    return get_stored_authorization_request_model().objects.create(
        request_uri=request_uri,
        client_id=client_id,
        parameters=parameters,
        expires=timezone.now() + timedelta(seconds=expires_in),
    )


def get_application_model():
    """Return the Application model that is active in this project."""
    return apps.get_model(oauth2_settings.APPLICATION_MODEL)


def get_device_grant_model():
    """Return the DeviceGrant model that is active in this project."""
    return apps.get_model(oauth2_settings.DEVICE_GRANT_MODEL)


def get_stored_authorization_request_model() -> type[AbstractStoredAuthorizationRequest]:
    """Return the StoredAuthorizationRequest model that is active in this project."""
    return apps.get_model(oauth2_settings.STORED_AUTHORIZATION_REQUEST_MODEL)


def get_grant_model():
    """Return the Grant model that is active in this project."""
    return apps.get_model(oauth2_settings.GRANT_MODEL)


def get_access_token_model():
    """Return the AccessToken model that is active in this project."""
    return apps.get_model(oauth2_settings.ACCESS_TOKEN_MODEL)


def get_id_token_model():
    """Return the IDToken model that is active in this project."""
    return apps.get_model(oauth2_settings.ID_TOKEN_MODEL)


def get_refresh_token_model():
    """Return the RefreshToken model that is active in this project."""
    return apps.get_model(oauth2_settings.REFRESH_TOKEN_MODEL)


def get_revoked_token_evidence_model():
    """Return the model that stores non-credential revocation evidence.

    It is not swappable: it holds no relation to a project's user or application models,
    only a checksum and identifiers, so a swapped token model does not need to replace it.
    """
    return RevokedTokenEvidence


def get_token_cleanup_run_model():
    """Return the model that records ``clear_expired`` run checkpoints."""
    return TokenCleanupRun


def get_application_admin_class():
    """Return the Application admin class that is active in this project."""
    application_admin_class = oauth2_settings.APPLICATION_ADMIN_CLASS
    return application_admin_class


def get_access_token_admin_class():
    """Return the AccessToken admin class that is active in this project."""
    access_token_admin_class = oauth2_settings.ACCESS_TOKEN_ADMIN_CLASS
    return access_token_admin_class


def get_grant_admin_class():
    """Return the Grant admin class that is active in this project."""
    grant_admin_class = oauth2_settings.GRANT_ADMIN_CLASS
    return grant_admin_class


def get_id_token_admin_class():
    """Return the IDToken admin class that is active in this project."""
    id_token_admin_class = oauth2_settings.ID_TOKEN_ADMIN_CLASS
    return id_token_admin_class


def get_refresh_token_admin_class():
    """Return the RefreshToken admin class that is active in this project."""
    refresh_token_admin_class = oauth2_settings.REFRESH_TOKEN_ADMIN_CLASS
    return refresh_token_admin_class


def refresh_token_expire_timedelta():
    """Return ``REFRESH_TOKEN_EXPIRE_SECONDS`` as a ``timedelta``, or ``None`` when refresh
    tokens do not age-expire (the setting is unset, ``0``, or ``timedelta(0)``).

    Raises ``ImproperlyConfigured`` for a non-numeric, out-of-range, or negative value
    (like ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS``) so that both the validation-time
    enforcement and ``clear_expired`` fail the same way on a misconfiguration instead of
    raising an opaque ``TypeError``/``OverflowError``.
    """
    value = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS
    if not value:
        return None
    if not isinstance(value, timedelta):
        try:
            value = timedelta(seconds=value)
        except (TypeError, OverflowError):
            raise ImproperlyConfigured("REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds")
    if value < timedelta(0):
        raise ImproperlyConfigured("REFRESH_TOKEN_EXPIRE_SECONDS must not be negative")
    return value


def refresh_token_evidence_retention_timedelta() -> timedelta | None:
    """Return ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` as a ``timedelta``.

    ``None`` (the default) keeps the pre-existing behaviour: reuse-detection evidence is
    retained for as long as the protections that are enabled require. An explicit value
    adds a *minimum* retention period on top of the grace period, and on top of the
    refresh-token lifetime when ``REFRESH_TOKEN_REUSE_PROTECTION`` is on. ``0`` adds
    nothing beyond the protections' own requirements.

    Raises ``ImproperlyConfigured`` for a non-numeric, out-of-range, or negative value,
    like :func:`refresh_token_expire_timedelta`, so a misconfiguration fails identically
    at validation time and in ``clear_expired``.
    """
    value = oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS
    if value is None:
        return None
    if not isinstance(value, timedelta):
        try:
            value = timedelta(seconds=value)
        except (TypeError, OverflowError):
            raise ImproperlyConfigured(
                "REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS must be either a timedelta or seconds"
            )
    if value < timedelta(0):
        raise ImproperlyConfigured("REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS must not be negative")
    return value


def refresh_token_grace_period_timedelta() -> timedelta:
    """Return ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS`` as a non-negative ``timedelta``.

    Shared by validation and cleanup so both interpret the window the same way and an
    invalid value fails the same way (``ImproperlyConfigured``).
    """
    value = oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS
    if not value:
        return timedelta(0)
    if not isinstance(value, timedelta):
        try:
            value = timedelta(seconds=value)
        except (TypeError, OverflowError):
            raise ImproperlyConfigured("REFRESH_TOKEN_GRACE_PERIOD_SECONDS must be in seconds")
    if value < timedelta(0):
        raise ImproperlyConfigured("REFRESH_TOKEN_GRACE_PERIOD_SECONDS must not be negative")
    return value


def revoked_refresh_token_retention() -> timedelta | None:
    """Return how long a revoked refresh token must be kept after revocation.

    ``None`` means "keep forever". What is required depends on what the setting is
    protecting:

    * the **grace period** is always required -- a rotation that superseded a token must
      still be recognizable so a retry within the window can be served. It is therefore
      the floor, regardless of what ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` says.
    * when ``REFRESH_TOKEN_REUSE_PROTECTION`` is on, the revoked row is *reuse-detection
      evidence*. It is required for ``REFRESH_TOKEN_EXPIRE_SECONDS``, and an explicit
      ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` can extend that (never shorten it below
      the refresh-token lifetime).
    * when reuse protection is off, a revoked row is not evidence for any live security
      decision. ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` is then an ordinary
      *retention cap* chosen by the operator's privacy policy, limited below only by the
      grace period. ``None`` means "fall back to the old schedule: just the grace period".

    The return value is a duration; the caller compares ``revoked <= now - retention``.
    """
    grace = refresh_token_grace_period_timedelta()
    retention = refresh_token_evidence_retention_timedelta()
    expire = refresh_token_expire_timedelta()
    if oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION:
        if expire is None and retention is None:
            return None
        keep = max(grace, expire) if expire is not None else grace
        if retention is not None:
            keep = max(keep, retention)
        return keep
    if retention is None:
        return grace
    return max(grace, retention)


def revocation_evidence_required() -> bool:
    """Whether a revoked refresh token backs a security decision worth preserving.

    Only reuse protection consumes revoked refresh-token rows as evidence. When it is off,
    a deleted revoked token cannot make anything usable: the token is unknown and is
    rejected as ``invalid_grant``. Keeping evidence for deleted accounts in that mode
    would retain personal data for no security benefit.
    """
    return bool(oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION)


@dataclass(frozen=True)
class TokenCleanupReport:
    """Outcome of :func:`clear_expired`, suitable for logs and cron output.

    It deliberately carries only counts, phase names and the cleanup run identifier. It
    never contains token values, token checksums, user identifiers or other credential
    material: a cleanup report is often shipped to a log aggregator.
    """

    run_id: int
    status: str
    phase: str
    counts: dict[str, int]
    batches: int
    cutoffs: dict[str, str | None]

    def as_dict(self) -> dict:
        """Return the report as JSON-serializable data (counts and non-sensitive ids)."""
        return {
            "run_id": self.run_id,
            "status": self.status,
            "phase": self.phase,
            "batches": self.batches,
            "counts": dict(self.counts),
            "cutoffs": dict(self.cutoffs),
        }


def revoke_access_token(access_token: AbstractAccessToken) -> None:
    """
    Revoke an access token and, if present, its bound refresh token.

    Deleting the access token on its own leaves the refresh token usable (the
    ``RefreshToken.access_token`` FK is ``SET_NULL``), so it can still be exchanged for a fresh
    access token, defeating the revocation. Per :rfc:`7009#section-2.1` revoking an access token
    MAY also revoke the bound refresh token; revoking the refresh token also deletes the bound
    access token, so it covers both. When there is no refresh token, revoke the access token
    directly (which deletes it).

    The bound refresh token is looked up with a forward query on the refresh token model rather
    than the reverse ``access_token.refresh_token`` accessor, whose name depends on the
    ``related_name`` a swapped refresh token model may override.

    This is the single revoke path shared by the ``/revoke/`` endpoint, the
    ``AuthorizedTokenDeleteView``, and the admin "Revoke selected access tokens" action. Whether a
    refresh token may *survive* access-token revocation is a policy deferred to 4.x (see #1786).
    """
    refresh_token = get_refresh_token_model().objects.filter(access_token=access_token).first()
    if refresh_token is not None:
        refresh_token.revoke()
    else:
        access_token.revoke()


CLEANUP_PHASE_EXPIRED_GRANTS = "expired_grants"
CLEANUP_PHASE_EXPIRED_STORED_REQUESTS = "expired_stored_authorization_requests"
CLEANUP_PHASE_ORPHANED_REFRESH_TOKENS = "orphaned_refresh_tokens"
CLEANUP_PHASE_EXPIRED_REFRESH_TOKENS = "expired_refresh_tokens"
CLEANUP_PHASE_REVOKED_REFRESH_TOKENS = "revoked_refresh_tokens"
CLEANUP_PHASE_EXPIRED_ACCESS_TOKENS = "expired_access_tokens"
CLEANUP_PHASE_EXPIRED_ID_TOKENS = "expired_id_tokens"
CLEANUP_PHASE_EXPIRED_REVOCATION_EVIDENCE = "expired_revocation_evidence"

# Ordered so that a single sweep reclaims as much as possible: rows that become
# deletable only once another row is gone (a refresh token whose access token then has no
# refresh token left) come after the phase that releases them. Every phase is idempotent,
# so a resumed run simply re-evaluates its query.
CLEANUP_PHASES = (
    CLEANUP_PHASE_EXPIRED_GRANTS,
    CLEANUP_PHASE_EXPIRED_STORED_REQUESTS,
    CLEANUP_PHASE_ORPHANED_REFRESH_TOKENS,
    CLEANUP_PHASE_EXPIRED_REFRESH_TOKENS,
    CLEANUP_PHASE_REVOKED_REFRESH_TOKENS,
    CLEANUP_PHASE_EXPIRED_ACCESS_TOKENS,
    CLEANUP_PHASE_EXPIRED_ID_TOKENS,
    CLEANUP_PHASE_EXPIRED_REVOCATION_EVIDENCE,
)


def _delete_cleanup_batch(model, query, run, phase, counts, batch_size, batch_interval):
    """Delete up to ``batch_size`` matching rows, checkpointing after each batch.

    Returns ``(deleted_rows, batch_count)``. Only primary keys are ever selected, so the
    function never materializes token values or checksums in memory or in the run row.
    Checkpointing after each batch is what makes an interrupted run resumable with
    accurate counts: the rows already deleted are recorded before the next batch starts.
    """
    pks = list(model._default_manager.filter(query).values_list("pk", flat=True)[:batch_size])
    if not pks:
        return 0, 0
    model._default_manager.filter(pk__in=pks).delete()
    deleted = len(pks)
    counts[phase] = counts.get(phase, 0) + deleted
    run.counts = counts
    run.batches = (run.batches or 0) + 1
    run.save(update_fields=["counts", "batches", "updated_at"])
    if batch_interval:
        time.sleep(batch_interval)
    return deleted, 1


def _run_cleanup_phase(model, query, run, phase, counts, batch_size, batch_interval):
    """Drain one phase in bounded batches, returning the total number of rows deleted."""
    total = 0
    batch_count = 0
    while True:
        deleted, batches = _delete_cleanup_batch(model, query, run, phase, counts, batch_size, batch_interval)
        if not deleted:
            break
        total += deleted
        batch_count += batches
    return total, batch_count


def clear_expired(*, resume: bool = False) -> TokenCleanupReport:
    """Delete token data that is no longer needed, in resumable phases.

    The sweep separates three kinds of data:

    * **Immediately deletable** -- expired grants, expired stored authorization requests,
      orphaned refresh tokens (no access token left to refresh against), idle-expired
      refresh tokens (only when ``REFRESH_TOKEN_EXPIRE_SECONDS`` is set), and expired
      access/ID tokens. None of these participate in a security decision any more;
      deleting them cannot make a revoked credential usable again.
    * **Still needed for reuse detection** -- revoked refresh tokens younger than the
      retention floor computed by :func:`revoked_refresh_token_retention`. With
      ``REFRESH_TOKEN_REUSE_PROTECTION`` on, these rows are exactly what lets a replay of
      a rotated token be recognized and its family revoked, so they are never deleted
      early. The retention is the longer of the grace period and, when reuse
      protection is on, the refresh-token lifetime -- optionally extended by an explicit
      ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS``.
    * **Past the evidence retention period** -- revoked refresh tokens older than that
      floor, and :class:`RevokedTokenEvidence` rows whose ``retain_until`` has passed.

    The run is checkpointed in :class:`TokenCleanupRun` after every batch. If it is
    interrupted and restarted with ``resume=True``, it continues at the phase it was in;
    because every phase is a pure deletion guarded by the same cutoff, restarting from
    any point converges on the same state and never resurrects a deleted credential.
    Without ``resume`` a fresh run starts and any unfinished run is marked interrupted.

    Returns a :class:`TokenCleanupReport` containing only counts, phase names and the
    run id -- never a token value, checksum or user identifier.
    """
    now = timezone.now()
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    id_token_model = get_id_token_model()
    grant_model = get_grant_model()
    stored_request_model = get_stored_authorization_request_model()

    # Validate every retention input up front: a misconfiguration must fail before any
    # row is deleted, not halfway through the sweep. The grace and evidence values are
    # read inside ``revoked_refresh_token_retention``; calling the helpers here only
    # surfaces a bad type/negative value before the first delete.
    refresh_token_grace_period_timedelta()
    expire = refresh_token_expire_timedelta()
    refresh_token_evidence_retention_timedelta()
    revoked_retention = revoked_refresh_token_retention()

    refresh_expire_at = now - expire if expire is not None else None
    revoked_retention_at = now - revoked_retention if revoked_retention is not None else None

    batch_size = oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_SIZE
    batch_interval = oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL

    if resume:
        run = (
            TokenCleanupRun.objects.filter(status__in=[TokenCleanupRun.RUNNING, TokenCleanupRun.INTERRUPTED])
            .order_by("-id")
            .first()
        )
    else:
        # A crashed process can leave a RUNNING row behind. Starting fresh supersedes it
        # rather than silently resuming a run the operator did not ask to continue.
        TokenCleanupRun.objects.filter(
            status__in=[TokenCleanupRun.RUNNING, TokenCleanupRun.INTERRUPTED]
        ).update(status=TokenCleanupRun.INTERRUPTED)
        run = None

    if run is None:
        run = TokenCleanupRun.objects.create(
            status=TokenCleanupRun.RUNNING,
            counts={},
            cutoffs={
                "refresh_expire_at": refresh_expire_at.isoformat() if refresh_expire_at else None,
                "revoked_retention_at": revoked_retention_at.isoformat() if revoked_retention_at else None,
                "now": now.isoformat(),
            },
        )

    counts = dict(run.counts or {})
    completed = set(run.completed_phases or [])
    phase = run.phase or CLEANUP_PHASES[0]
    # Resume at the recorded phase if the restarted retention inputs still identify the
    # same cutoff. If the operator changed settings between runs, a phase that has not
    # completed is re-evaluated with the new cutoff on the same data, which is safe but
    # the stored finished-phase counts from the old policy are no longer meaningful.
    if phase not in CLEANUP_PHASES:
        phase = CLEANUP_PHASES[0]

    def finish(phase_name):
        completed.add(phase_name)
        run.completed_phases = sorted(completed)
        run.phase = phase_name
        run.status = TokenCleanupRun.RUNNING
        run.save(update_fields=["completed_phases", "phase", "status", "updated_at"])

    def run_phase(phase_name, model, query):
        # Phases that already finished in this run are not repeated. A phase that was
        # interrupted mid-way has partial counts stored from the batches it completed;
        # re-running its query only removes rows that still match, so no double count
        # of already-deleted rows can occur.
        if phase_name in completed:
            return 0
        if phase_name not in counts:
            counts[phase_name] = 0
        run.phase = phase_name
        run.save(update_fields=["phase", "updated_at"])
        deleted, _ = _run_cleanup_phase(model, query, run, phase_name, counts, batch_size, batch_interval)
        finish(phase_name)
        logger.info("%s rows deleted in cleanup phase %s", deleted, phase_name)
        return deleted

    def phase_expired_grants():
        return run_phase(CLEANUP_PHASE_EXPIRED_GRANTS, grant_model, models.Q(expires__lt=now))

    def phase_expired_stored_requests():
        return run_phase(
            CLEANUP_PHASE_EXPIRED_STORED_REQUESTS,
            stored_request_model,
            models.Q(expires__lt=now),
        )

    def phase_orphaned_refresh_tokens():
        # A non-revoked refresh token with no access token can never be refreshed and can
        # not participate in reuse detection (nothing was rotated past it), so it is safe
        # to delete regardless of REFRESH_TOKEN_EXPIRE_SECONDS (#746).
        return run_phase(
            CLEANUP_PHASE_ORPHANED_REFRESH_TOKENS,
            refresh_token_model,
            models.Q(revoked__isnull=True, access_token__isnull=True),
        )

    def phase_expired_refresh_tokens():
        if refresh_expire_at is None:
            logger.info("refresh_expire_at is None. No expired refresh tokens deleted.")
            finish(CLEANUP_PHASE_EXPIRED_REFRESH_TOKENS)
            return 0
        # ``__lte`` so a token whose access token expired exactly at the cutoff is
        # reclaimed, matching AccessToken.is_expired() (``now >= expires``).
        return run_phase(
            CLEANUP_PHASE_EXPIRED_REFRESH_TOKENS,
            refresh_token_model,
            models.Q(revoked__isnull=True, access_token__expires__lte=refresh_expire_at),
        )

    def phase_revoked_refresh_tokens():
        if revoked_retention_at is None:
            logger.info(
                "revoked refresh token evidence is retained indefinitely; no revoked "
                "refresh tokens deleted."
            )
            finish(CLEANUP_PHASE_REVOKED_REFRESH_TOKENS)
            return 0
        return run_phase(
            CLEANUP_PHASE_REVOKED_REFRESH_TOKENS,
            refresh_token_model,
            models.Q(revoked__lte=revoked_retention_at),
        )

    def phase_expired_access_tokens():
        return run_phase(
            CLEANUP_PHASE_EXPIRED_ACCESS_TOKENS,
            access_token_model,
            models.Q(refresh_token__isnull=True, expires__lt=now),
        )

    def phase_expired_id_tokens():
        return run_phase(
            CLEANUP_PHASE_EXPIRED_ID_TOKENS,
            id_token_model,
            models.Q(access_token__isnull=True, expires__lt=now),
        )

    def phase_expired_revocation_evidence():
        # ``retain_until`` NULL means "retain forever", so it is never matched here.
        return run_phase(
            CLEANUP_PHASE_EXPIRED_REVOCATION_EVIDENCE,
            RevokedTokenEvidence,
            models.Q(retain_until__lte=now),
        )

    phase_functions = {
        CLEANUP_PHASE_EXPIRED_GRANTS: phase_expired_grants,
        CLEANUP_PHASE_EXPIRED_STORED_REQUESTS: phase_expired_stored_requests,
        CLEANUP_PHASE_ORPHANED_REFRESH_TOKENS: phase_orphaned_refresh_tokens,
        CLEANUP_PHASE_EXPIRED_REFRESH_TOKENS: phase_expired_refresh_tokens,
        CLEANUP_PHASE_REVOKED_REFRESH_TOKENS: phase_revoked_refresh_tokens,
        CLEANUP_PHASE_EXPIRED_ACCESS_TOKENS: phase_expired_access_tokens,
        CLEANUP_PHASE_EXPIRED_ID_TOKENS: phase_expired_id_tokens,
        CLEANUP_PHASE_EXPIRED_REVOCATION_EVIDENCE: phase_expired_revocation_evidence,
    }

    # Resume in phase order but never skip a phase the interrupted run never finished. The
    # recorded phase may itself be complete (the interruption landed after its last batch),
    # so the pending set is recomputed from ``completed`` and then trimmed at the first
    # *pending* phase at or after the recorded one.
    remaining = [name for name in CLEANUP_PHASES if name not in completed]
    if phase in CLEANUP_PHASES:
        start_index = CLEANUP_PHASES.index(phase)
        resumed = [name for name in remaining if CLEANUP_PHASES.index(name) >= start_index]
        if resumed:
            remaining = resumed

    try:
        for phase_name in remaining:
            phase_functions[phase_name]()
    except (KeyboardInterrupt, SystemExit):
        # Persist enough state for ``resume=True`` to continue where this stopped. The
        # rows deleted so far stay deleted; the phases still pending are re-evaluated on
        # the next run, and their cutoffs are recomputed against the new ``now``.
        TokenCleanupRun.objects.filter(pk=run.pk).update(status=TokenCleanupRun.INTERRUPTED, phase=run.phase)
        raise
    except Exception:
        TokenCleanupRun.objects.filter(pk=run.pk).update(status=TokenCleanupRun.FAILED, phase=run.phase)
        raise

    run.refresh_from_db()
    run.status = TokenCleanupRun.COMPLETED
    run.phase = CLEANUP_PHASES[-1]
    run.completed_phases = list(CLEANUP_PHASES)
    run.save(update_fields=["status", "phase", "completed_phases", "updated_at"])

    report = TokenCleanupReport(
        run_id=run.pk,
        status=run.status,
        phase=run.phase,
        counts={name: counts.get(name, 0) for name in CLEANUP_PHASES},
        batches=run.batches,
        cutoffs=dict(run.cutoffs or {}),
    )
    logger.info(
        "token cleanup run %s completed: %s",
        report.run_id,
        ", ".join(f"{name}={report.counts[name]}" for name in CLEANUP_PHASES),
    )
    return report


def purge_user_credentials(user) -> dict[str, int]:
    """Delete a user's OAuth credentials while keeping the minimum revocation evidence.

    Call this *before* deleting the Django user (or instead of relying on the ``CASCADE``
    that deleting the user performs), when reuse-detection evidence has to outlive the
    account. It implements the coexistence rule the cleanup policy needs:

    * every credential row belonging to the user -- access tokens, refresh tokens, ID
      tokens, grants and device grants -- is deleted, so no credential remains usable;
    * for each **revoked** refresh token whose retention period has not passed, one
      :class:`RevokedTokenEvidence` row is written first -- but only when
      ``REFRESH_TOKEN_REUSE_PROTECTION`` is on, because that judgment is the only thing
      that consumes it. The row holds only the token's SHA-256 checksum, its family id,
      the client id and the retention deadline. It lets a replay of a purged token still
      be recognized (and its family revoked via
      :func:`OAuth2Validator.validate_refresh_token`) without keeping a raw token, a user
      reference, a scope or an application foreign key;
    * live (non-revoked) refresh tokens need no evidence: once deleted, a replay is an
      unknown token and is rejected as ``invalid_grant``. Copying them would retain more
      personal data than the security judgment needs.

    Returns counts keyed by data type (no token values and no user identifiers), so the
    caller can log an account-deletion result without leaking credential material.
    """
    now = timezone.now()
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    id_token_model = get_id_token_model()
    grant_model = get_grant_model()
    device_grant_model = get_device_grant_model()

    keep_evidence = revocation_evidence_required()
    retention = revoked_refresh_token_retention()
    counts = {
        "revoked_evidence_created": 0,
        "refresh_tokens_deleted": 0,
        "access_tokens_deleted": 0,
        "id_tokens_deleted": 0,
        "grants_deleted": 0,
        "device_grants_deleted": 0,
    }

    revoked_tokens = list(
        refresh_token_model.objects.filter(user=user, revoked__isnull=False).values(
            "token_checksum", "token_family", "revoked", "application__client_id"
        )
    )
    for token in revoked_tokens:
        if not keep_evidence:
            # No live security decision reads this row, so the account deletion keeps
            # nothing: the token will simply be unknown.
            continue
        retain_until = None
        if retention is not None:
            retain_until = token["revoked"] + retention
            if retain_until <= now:
                # Past the evidence retention period: nothing to preserve.
                continue
        client_id = token["application__client_id"] or ""
        evidence, created = RevokedTokenEvidence.objects.update_or_create(
            token_checksum=token["token_checksum"],
            defaults={
                "token_family": token["token_family"],
                "client_id": client_id,
                "revoked_at": token["revoked"],
                "retain_until": retain_until,
            },
        )
        if created:
            counts["revoked_evidence_created"] += 1

    # Deleting the refresh tokens first deletes the access tokens bound to them
    # (``RefreshToken.revoke()`` normally already did), then the explicit access-token
    # delete reclaims the rest. Announcement counts are taken before each delete.
    deletion_specs = (
        ("refresh_tokens_deleted", refresh_token_model, models.Q(user=user)),
        ("access_tokens_deleted", access_token_model, models.Q(user=user)),
        ("id_tokens_deleted", id_token_model, models.Q(user=user)),
        ("grants_deleted", grant_model, models.Q(user=user)),
        ("device_grants_deleted", device_grant_model, models.Q(user=user)),
    )
    for key, model, query in deletion_specs:
        counts[key] = model._default_manager.filter(query).count()
        model._default_manager.filter(query).delete()

    logger.info(
        "purged credentials for a deleted account: %s",
        ", ".join(f"{key}={value}" for key, value in counts.items()),
    )
    return counts


# Neither side of the comparison is trusted to be bounded.  The requested URI is
# client input, and the registered URIs only look like operator configuration: under
# RFC 7591 dynamic registration and CIMD they are supplied by the registrant, and
# neither path caps their length or their number.  256 characters is well past any
# legitimate redirect URI, and 10 candidates past any legitimate client, while both
# stay short enough that a flood of junk cannot fill the log.
_MAX_LOGGED_URI_LENGTH = 256
_MAX_LOGGED_CANDIDATES = 10


def _loggable_uri(uri: Optional[str]) -> str:
    """
    Render a client-supplied URI for inclusion in a log message.

    The value is truncated, and rendered with ``repr()`` so that control
    characters -- CR/LF above all -- are escaped rather than forging log lines.

    :param uri: URI to render
    """
    if uri is None:
        return "None"
    if len(uri) > _MAX_LOGGED_URI_LENGTH:
        uri = uri[:_MAX_LOGGED_URI_LENGTH] + "...[truncated]"
    return repr(uri)


def _format_uri_mismatch_reasons(reasons: list[tuple[Optional[str], str]]) -> str:
    """
    Render the reasons collected by :func:`check_redirect_to_uri_allowed` as one
    log-friendly string.

    Candidates are rendered through :func:`_loggable_uri` for the same reason the
    requested URI is: a registered URI can be registrant-supplied and unbounded.

    :param reasons: ``(candidate, reason)`` pairs; a ``None`` candidate is a
        rejection of the requested URI itself rather than of a registered one
    """
    if not reasons:
        return "no URIs are registered"
    listed = "; ".join(
        reason if candidate is None else "{0}: {1}".format(_loggable_uri(candidate), reason)
        for candidate, reason in reasons[:_MAX_LOGGED_CANDIDATES]
    )
    remaining = len(reasons) - _MAX_LOGGED_CANDIDATES
    if remaining > 0:
        listed += "; ...and {0} further registered URI(s) not listed".format(remaining)
    return listed


def _log_registered_uri_mismatch(
    uri_type: str, uri: str, client_id: str, reasons: list[tuple[Optional[str], str]]
) -> None:
    """
    Log why a client-supplied URI matched none of the URIs registered for a client.

    Without this the mismatch reaches the developer as nothing but oauthlib's bare
    "Mismatching redirect URI." (see #681).  The detail is deliberately confined to
    the log and must never be added to the error response: that response is
    rendered to whoever made the request, so it would let an unauthenticated caller
    read back a client's registered URIs by sending a junk URI with a known
    client_id.

    :param uri_type: name of the parameter being checked, for the log message
    :param uri: the client-supplied URI that was rejected
    :param client_id: client whose registered URIs were checked
    :param reasons: ``(candidate, reason)`` pairs from :func:`check_redirect_to_uri_allowed`
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    logger.debug(
        "%s %s does not match any %s registered for client_id %r: %s",
        uri_type,
        _loggable_uri(uri),
        uri_type,
        client_id,
        _format_uri_mismatch_reasons(reasons),
    )


def check_redirect_to_uri_allowed(
    uri: str, allowed_uris: list[str]
) -> tuple[bool, list[tuple[Optional[str], str]]]:
    """
    Same check as :func:`redirect_to_uri_allowed`, additionally reporting why the
    URI was rejected.

    Returns ``(allowed, reasons)``.  ``reasons`` is only meaningful when
    ``allowed`` is ``False``: it holds one ``(candidate, reason)`` pair for every
    registered URI that failed to match, plus pairs with a ``None`` candidate for
    rejections of the requested URI itself.  A reason names the component that
    differs instead of echoing the requested URI back, which callers log once and
    only after passing it through :func:`_loggable_uri`.

    :param uri: URI to check
    :param allowed_uris: A list of URIs that are allowed
    """

    if not isinstance(allowed_uris, list):
        raise ValueError("allowed_uris must be a list")

    reasons: list[tuple[Optional[str], str]] = []

    # urlsplit() rather than urlparse(): urlparse() peels ";params" off the last
    # path segment into a separate attribute, so comparing .path alone would let a
    # request smuggle "/cb;evil=1" past a registered "/cb".  urlsplit() leaves the
    # parameters in .path, where they are compared like the rest of it.
    parsed_uri = urlsplit(uri)

    # RFC 6749 section 3.1.2: "The endpoint URI MUST NOT include a fragment
    # component."  Test the raw string rather than .fragment, which is "" both for
    # a URI with no fragment and for one ending in a bare "#" -- the latter is a
    # (empty) fragment component and is not the registered URI.  A percent-encoded
    # %23 is not a fragment delimiter and is unaffected.
    if "#" in uri:
        return False, [(None, "the requested URI has a fragment, which RFC 6749 section 3.1.2 forbids")]

    # Credentials are not part of a registered callback and must not ride along on
    # the request; without this "https://evil@example.com/cb" would match a
    # registered "https://example.com/cb", since only .hostname is compared below.
    if "@" in parsed_uri.netloc:
        return False, [(None, "the requested URI carries userinfo credentials in its authority")]

    # .port raises ValueError for a non-numeric or out-of-range port.
    try:
        uri_port = parsed_uri.port
    except ValueError:
        return False, [(None, "the requested URI has a malformed port")]

    for allowed_uri in allowed_uris:
        # A registered URI carrying a fragment or credentials cannot authorize
        # anything: the request forms that would match it are rejected above.
        if "#" in allowed_uri:
            reasons.append((allowed_uri, "the registered URI has a fragment and can never match"))
            continue

        parsed_allowed_uri = urlsplit(allowed_uri)

        if "@" in parsed_allowed_uri.netloc:
            reasons.append(
                (allowed_uri, "the registered URI carries userinfo credentials and can never match")
            )
            continue

        try:
            allowed_uri_port = parsed_allowed_uri.port
        except ValueError:
            reasons.append((allowed_uri, "the registered URI has a malformed port and can never match"))
            continue

        if parsed_allowed_uri.scheme != parsed_uri.scheme:
            # match failed, continue
            reasons.append((allowed_uri, "scheme differs"))
            continue

        """ check hostname """
        # A private-use URI scheme redirect (RFC 8252 §7.1) has no naming
        # authority, so hostname is None on either side; guard before matching.
        allowed_hostname = parsed_allowed_uri.hostname
        uri_hostname = parsed_uri.hostname
        if oauth2_settings.ALLOW_URI_WILDCARDS and allowed_hostname and allowed_hostname.startswith("*"):
            """ wildcard hostname """
            if not uri_hostname or not uri_hostname.endswith(allowed_hostname[1:]):
                reasons.append((allowed_uri, "hostname does not match the registered wildcard"))
                continue
        elif allowed_hostname != uri_hostname:
            reasons.append((allowed_uri, "hostname differs"))
            continue

        # From RFC 8252 (Section 7.3)
        # https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
        #
        # Loopback redirect URIs use the "http" scheme
        # [...]
        # The authorization server MUST allow any port to be specified at the
        # time of the request for loopback IP redirect URIs, to accommodate
        # clients that obtain an available ephemeral port from the operating
        # system at the time of the request.
        #
        # Section 8.3 notes that "localhost" redirect URIs "function similarly
        # to loopback IP redirects" but their use is NOT RECOMMENDED, so the
        # port exemption is not extended to the "localhost" hostname by
        # default.  Some native clients nonetheless register "localhost" and
        # receive the callback on an ephemeral port; ALLOW_LOCALHOST_LOOPBACK
        # opts in to treating it as loopback.  The hostname must still match
        # exactly, so "localhost" is never conflated with the IP literals.
        allowed_uri_is_loopback = parsed_allowed_uri.scheme == "http" and (
            parsed_allowed_uri.hostname in ("127.0.0.1", "::1")
            or (oauth2_settings.ALLOW_LOCALHOST_LOOPBACK and parsed_allowed_uri.hostname == "localhost")
        )
        """ check port """
        if not allowed_uri_is_loopback and allowed_uri_port != uri_port:
            reasons.append((allowed_uri, "port differs"))
            continue

        """ check path """
        if parsed_allowed_uri.path != parsed_uri.path:
            reasons.append((allowed_uri, "path differs"))
            continue

        """ check querystring """
        # RFC 9700 section 2.1 requires exact matching of the redirect URI (see
        # also OpenID Connect Core section 3.1.2.1, which mandates RFC 3986
        # section 6.2.1 Simple String Comparison).  This previously tested that
        # the registered query was a *subset* of the requested one, which let a
        # request carry query parameters that were never registered: an attacker
        # could append parameters to an otherwise-legitimate redirect URI and
        # have the authorization server reflect them into the client's callback
        # alongside the authorization code (RFC 9700 section 4.1).
        #
        # .query is "" both when there is no query component and when there is an
        # empty one ("https://example.com/cb?"), which are different URIs under
        # simple string comparison, so the delimiter's presence is compared too.
        # A "?" cannot appear in a scheme, authority or path -- the first one always
        # opens the query -- so testing the raw string is equivalent to testing for
        # the component.  A percent-encoded %3F is not a delimiter and is unaffected.
        if ("?" in allowed_uri) != ("?" in uri):
            reasons.append((allowed_uri, "one URI has a query component and the other does not"))
            continue
        if parsed_allowed_uri.query != parsed_uri.query:
            reasons.append((allowed_uri, "query string differs"))
            continue  # circuit break

        return True, []

    # if uris matched then it's not allowed
    return False, reasons


def redirect_to_uri_allowed(uri: str, allowed_uris: list[str]) -> bool:
    """
    Checks if a given uri can be redirected to based on the provided allowed_uris configuration.

    On top of exact matches, this function also handles loopback IPs based on RFC 8252.

    :param uri: URI to check
    :param allowed_uris: A list of URIs that are allowed
    """
    allowed, _reasons = check_redirect_to_uri_allowed(uri, allowed_uris)
    return allowed


def is_origin_allowed(origin, allowed_origins):
    """
    Checks if a given origin uri is allowed based on the provided allowed_origins configuration.

    :param origin: Origin URI to check
    :param allowed_origins: A list of Origin URIs that are allowed
    """

    parsed_origin = urlparse(origin)

    if parsed_origin.scheme not in oauth2_settings.ALLOWED_SCHEMES:
        return False

    for allowed_origin in allowed_origins:
        parsed_allowed_origin = urlparse(allowed_origin)
        if (
            parsed_allowed_origin.scheme == parsed_origin.scheme
            and parsed_allowed_origin.netloc == parsed_origin.netloc
        ):
            return True

    return False
