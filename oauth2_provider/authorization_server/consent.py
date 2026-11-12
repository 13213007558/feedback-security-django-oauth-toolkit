"""Versioned data-usage consent backend.

The resource owner consents to a particular *version* of the data-usage terms,
not to an abstract application: the backend names the version the consent page
currently displays (:meth:`BaseConsentBackend.get_consent_version`) and decides
whether a consent recorded under an older version still authorizes a request
(:meth:`BaseConsentBackend.is_consent_valid`).

The recorded version travels with the consent itself: the signed authorization
form carries it onto the grant (and, for the implicit/hybrid flows, straight
onto the tokens), the code exchange copies it onto the access and refresh
tokens, and a refresh keeps it. Every token therefore answers "which consent
am I exercising?" without trusting whatever version the backend serves later.

The default :class:`StaticConsentBackend` returns the empty version and never
invalidates, so installations that do not version their terms keep the exact
behavior they had before this existed.
"""

from typing import TYPE_CHECKING

from oauth2_provider.settings import oauth2_settings

if TYPE_CHECKING:
    from django.http import HttpRequest

    from oauth2_provider.models import AbstractApplication


class BaseConsentBackend:
    """Pluggable source of consent versions and invalidation policy."""

    def get_consent_version(
        self, request: "HttpRequest", application: "AbstractApplication | None" = None
    ) -> str:
        """
        Return the identifier of the data-usage terms version the consent page
        must display for ``request``/``application``.

        The value is treated as opaque: any non-empty string that stays stable
        for an unchanged document and changes when the document changes. It is
        rendered on the consent page, signed into the form, and stored on the
        grant and tokens.
        """
        raise NotImplementedError

    def is_consent_valid(
        self,
        consented_version: str,
        current_version: str,
        request: "HttpRequest | None" = None,
        application: "AbstractApplication | None" = None,
    ) -> bool:
        """
        Whether consent recorded under ``consented_version`` still covers a
        request made while :meth:`get_consent_version` returns
        ``current_version``.

        Returning ``False`` makes the authorization endpoint show the consent
        page again (or answer ``consent_required`` to a ``prompt=none``
        request) and, when ``CONSENT_VERSION_ENFORCE_ON_REFRESH`` is enabled,
        makes the token endpoint reject a refresh whose tokens predate the
        current version.

        Implementations decide what counts as compatible. A policy that only
        widens the terms it grants can compare the versions; one whose
        documents may shrink or re-scope the data access should require an
        exact match so a version change can never silently widen what a token
        may do.
        """
        raise NotImplementedError


class StaticConsentBackend(BaseConsentBackend):
    """
    The default backend for installations without versioned terms.

    It always reports the empty version and never invalidates a consent, so the
    grant and token rows keep an empty ``consent_version`` and every flow
    behaves exactly as it did before consent versioning existed.
    """

    def get_consent_version(
        self, request: "HttpRequest", application: "AbstractApplication | None" = None
    ) -> str:
        return ""

    def is_consent_valid(
        self,
        consented_version: str,
        current_version: str,
        request: "HttpRequest | None" = None,
        application: "AbstractApplication | None" = None,
    ) -> bool:
        return True


def get_consent_backend() -> BaseConsentBackend:
    """Instantiate the configured consent backend."""
    return oauth2_settings.CONSENT_BACKEND_CLASS()
