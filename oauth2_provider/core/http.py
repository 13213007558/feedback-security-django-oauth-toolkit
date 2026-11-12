from urllib.parse import urlparse

from django.core.exceptions import DisallowedRedirect
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.encoding import iri_to_uri

from oauth2_provider.authorization_server.response_modes import form_post_parameters


class OAuth2ResponseRedirect(HttpResponse):
    """
    An HTTP 302 redirect with an explicit list of allowed schemes.
    Works like django.http.HttpResponseRedirect but we customize it
    to give us more flexibility on allowed scheme validation.
    """

    status_code = 302

    def __init__(self, redirect_to, allowed_schemes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self["Location"] = iri_to_uri(redirect_to)
        self.allowed_schemes = allowed_schemes
        self.validate_redirect(redirect_to)

    @property
    def url(self):
        return self["Location"]

    def validate_redirect(self, redirect_to):
        parsed = urlparse(str(redirect_to))
        if not parsed.scheme:
            raise DisallowedRedirect("OAuth2 redirects require a URI scheme.")
        if parsed.scheme not in self.allowed_schemes:
            raise DisallowedRedirect("Redirect to scheme {!r} is not permitted".format(parsed.scheme))


class OAuth2FormPostResponse(HttpResponse):
    """
    A 200 response that delivers an authorization response by auto-submitting a
    form POST to the registered redirect URI (OAuth 2.0 Form Post Response Mode).

    The target is validated against ``allowed_schemes`` exactly like
    :class:`OAuth2ResponseRedirect` validates a redirect target, so the two
    response modes trust the same URIs. The response parameters never appear in
    the URL: they are rendered as hidden controls. The page is marked
    non-cacheable and not to be sent as a ``Referer`` (Form Post Response Mode
    §4.2.1), and carries no link or other content that repeats the parameters, so
    the credentials cannot leak that way either.
    """

    status_code = 200
    template_name = "oauth2_provider/form_post.html"

    def __init__(self, redirect_to, allowed_schemes, redirect_uri=None, *args, **kwargs):
        self.allowed_schemes = allowed_schemes
        self.validate_redirect(redirect_to)
        action, fields = form_post_parameters(redirect_to, redirect_uri)
        content = render_to_string(self.template_name, {"action": action, "fields": fields})
        super().__init__(content=content, *args, **kwargs)
        # Form Post Response Mode §4.2.1: the response holds the authorization
        # result, so it must not be cached or stored (history included).
        self["Cache-Control"] = "no-store, no-cache"
        self["Pragma"] = "no-cache"
        # Keep the response parameters out of any Referer header the browser
        # sends when following the form POST to the client.
        self["Referrer-Policy"] = "no-referrer"

    def validate_redirect(self, redirect_to):
        parsed = urlparse(str(redirect_to))
        if not parsed.scheme:
            raise DisallowedRedirect("OAuth2 redirects require a URI scheme.")
        if parsed.scheme not in self.allowed_schemes:
            raise DisallowedRedirect("Redirect to scheme {!r} is not permitted".format(parsed.scheme))
