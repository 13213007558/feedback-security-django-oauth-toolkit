from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

from oauth2_provider.settings import oauth2_settings


#: A scope description a backend cannot vouch for. The consent page must not
#: show anything for such a scope (see ``get_scope_description``), so its decision
#: cannot be based on a placeholder.
UNRELIABLE_SCOPE_DESCRIPTION = _(
    "This permission cannot be described reliably right now, so it cannot be granted."
)


class BaseScopes:
    def get_all_scopes(self):
        """
        Return a dict-like object with all the scopes available in the
        system. The key should be the scope name and the value should be
        the description.

        ex: {"read": "A read scope", "write": "A write scope"}
        """
        raise NotImplementedError("")

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        """
        Return a list of scopes available for the current application/request.

        TODO: add info on where and why this method is called.

        ex: ["read", "write"]
        """
        raise NotImplementedError("")

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        """
        Return a list of the default scopes for the current application/request.
        This MUST be a subset of the scopes returned by `get_available_scopes`.

        TODO: add info on where and why this method is called.

        ex: ["read"]
        """
        raise NotImplementedError("")

    def get_scope_description(self, scope, application=None, request=None, *args, **kwargs):
        """
        Return the human-readable description of ``scope`` shown on the consent
        page, or ``None`` when no reliable description can be produced.

        A description identifies the *scope name* the user is consenting to: it is
        displayed next to the scope and is bound to it, never used as a key. A
        description that is missing, blank, not a string or otherwise unreliable is
        reported as ``None``, and a scope without a reliable description is not
        granted (the consent page refuses it rather than guessing).

        The default reads ``get_all_scopes()``; override it when descriptions come
        from somewhere else, or when they depend on the ``application``/``request``.
        """
        try:
            description = self.get_all_scopes().get(scope)
        except Exception:
            return None
        return description if _is_reliable_description(description) else None


def _is_reliable_description(description) -> bool:
    """Whether ``description`` can be shown, and bound, as the text of a scope.

    A lazy translation counts: its message id is its identity, and it is rendered
    in the active language (``oauth2_provider.authorization_server.consent``).
    Anything else that is not a non-blank string is unreliable.
    """
    if isinstance(description, Promise):
        args = getattr(description, "_args", ())
        kwargs = getattr(description, "_kw", {}) or {}
        message = args[0] if args else kwargs.get("singular")
        return isinstance(message, str) and bool(message.strip())
    return isinstance(description, str) and bool(description.strip())


class SettingsScopes(BaseScopes):
    def get_all_scopes(self):
        return oauth2_settings.SCOPES

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        return oauth2_settings._SCOPES

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        return oauth2_settings._DEFAULT_SCOPES


def get_scopes_backend():
    scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
    return scopes_class()
