"""
Authorization-response encoding (OAuth 2.0 Multiple Response Type Encoding Practices).

The authorization endpoint returns its parameters either in the query, in the
fragment of the redirect URI, or as a form POST
(`OAuth 2.0 Form Post Response Mode <https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html>`_).
These helpers choose between them the same way for successful and error
responses, as OpenID Connect Core 3.2.2.6 and 3.3.2.6 require.
"""

from urllib.parse import parse_qsl, urlparse

from oauth2_provider.settings import oauth2_settings


def response_type_requires_fragment(response_type: str | None) -> bool:
    """
    Return whether ``response_type`` must be returned in the fragment.

    Any response type that includes ``token`` or ``id_token`` returns credentials in
    the front channel. Its default response mode is ``fragment``, and the query
    encoding must not be used for it (OAuth 2.0 Multiple Response Type Encoding
    Practices §§2.1, 3 and 5).
    """
    return bool(set((response_type or "").split()) & {"token", "id_token"})


#: The Form Post Response Mode name (OAuth 2.0 Form Post Response Mode).
FORM_POST_RESPONSE_MODE = "form_post"

#: The response modes this authorization server supports.
SUPPORTED_RESPONSE_MODES = ("query", "fragment", FORM_POST_RESPONSE_MODE)


def form_post_response_mode_enabled() -> bool:
    """
    Return whether the optional Form Post Response Mode is enabled.

    It is enabled by default; set the ``FORM_POST_RESPONSE_MODE_ENABLED``
    :mod:`oauth2_provider` setting to ``False`` to keep refusing
    ``response_mode=form_post`` as earlier releases did.
    """
    return bool(oauth2_settings.FORM_POST_RESPONSE_MODE_ENABLED)


def response_mode_permitted(response_type: str | None, response_mode: str) -> bool:
    """
    Return whether an explicitly requested ``response_mode`` can be honoured.

    Only the modes in :data:`SUPPORTED_RESPONSE_MODES` are supported (with
    ``form_post`` additionally gated by :func:`form_post_response_mode_enabled`),
    and ``query`` is not permitted for a response type that must use the
    fragment. Form Post is permitted for every response type: the parameters
    leave the URL either way, so it is usable for the implicit and hybrid flows
    too (Form Post Response Mode §2).
    """
    if response_mode not in SUPPORTED_RESPONSE_MODES:
        return False
    if response_mode == FORM_POST_RESPONSE_MODE and not form_post_response_mode_enabled():
        return False
    return not (response_mode == "query" and response_type_requires_fragment(response_type))


def authorization_response_uses_fragment(response_type: str | None, response_mode: str | None) -> bool:
    """
    Return whether an authorization response is encoded in the redirect URI fragment.

    Response types that must use the fragment always do, even if the request asked
    for ``response_mode=query``: such a request is rejected, and its error must not
    be returned in the query. Other response types use the fragment only if it was
    requested explicitly. A ``form_post`` response never uses the fragment, since
    its parameters are encoded in the POST body instead.
    """
    if response_mode == FORM_POST_RESPONSE_MODE:
        return False
    return response_type_requires_fragment(response_type) or response_mode == "fragment"


def supported_response_modes() -> tuple[str, ...]:
    """
    The response modes to publish in the discovery documents.

    Mirrors what :func:`response_mode_permitted` accepts, so a mode the server
    advertises is always honoured: ``form_post`` is omitted while the feature is
    switched off by ``FORM_POST_RESPONSE_MODE_ENABLED``.
    """
    if form_post_response_mode_enabled():
        return SUPPORTED_RESPONSE_MODES
    return tuple(mode for mode in SUPPORTED_RESPONSE_MODES if mode != FORM_POST_RESPONSE_MODE)


def form_post_parameters(url: str, redirect_uri: str | None = None) -> tuple[str, list[tuple[str, str]]]:
    """
    Split a redirect URL built for an authorization response into its form-post parts.

    Return ``(action, fields)`` where ``action`` is the redirect URI the client
    registered and ``fields`` is the ordered, decoded list of ``(name, value)``
    pairs to render as hidden form controls.

    When the validated ``redirect_uri`` is known it is used as the action, which
    keeps any query component the registered URI had; the response parameters are
    then whatever follows it in ``url``. Otherwise the parameters are read from
    the fragment, or from the whole query string; the registered redirect URI
    itself carries no fragment (RFC 6749 §3.1.2), so any fragment is entirely
    response parameters.
    """
    parsed = urlparse(url)
    if redirect_uri:
        action = redirect_uri
        if parsed.fragment:
            encoded = parsed.fragment
        elif url.startswith(redirect_uri):
            encoded = url[len(redirect_uri) :].lstrip("?&#")
        else:
            encoded = parsed.query
    elif parsed.fragment:
        action = parsed._replace(fragment="").geturl()
        encoded = parsed.fragment
    else:
        action = parsed._replace(query="", fragment="").geturl()
        encoded = parsed.query
    return action, parse_qsl(encoded, keep_blank_values=True)


def add_params_to_authorization_redirect(
    redirect_uri: str, params: str, response_type: str | None, response_mode: str | None
) -> str:
    """
    Append url-encoded authorization-response ``params`` to ``redirect_uri``.

    The parameters go in the fragment or the query according to
    :func:`authorization_response_uses_fragment`. A registered redirect URI has no
    fragment (RFC 6749 §3.1.2), so the fragment is the parameters alone.
    """
    if authorization_response_uses_fragment(response_type, response_mode):
        return f"{redirect_uri}#{params}"
    separator = "&" if "?" in redirect_uri else "?"
    return redirect_uri + separator + params
