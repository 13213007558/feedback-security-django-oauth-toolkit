import pytest

from oauth2_provider.authorization_server import response_modes


@pytest.mark.parametrize(
    "response_type, response_mode, expected",
    [
        ("code", None, False),
        ("none", None, False),
        (None, None, False),
        ("token", None, True),
        ("id_token", None, True),
        ("id_token token", None, True),
        ("code id_token", None, True),
        ("code token", None, True),
        ("code id_token token", None, True),
        # query is rejected for fragment response types, so their errors stay in the fragment.
        ("id_token", "query", True),
        ("code token", "query", True),
        ("code", "query", False),
        ("code", "fragment", True),
        ("none", "fragment", True),
        # form_post never uses the fragment: its parameters go in the POST body.
        ("code", "form_post", False),
    ],
)
def test_authorization_response_uses_fragment(response_type, response_mode, expected):
    assert response_modes.authorization_response_uses_fragment(response_type, response_mode) is expected


@pytest.mark.parametrize(
    "redirect_uri, response_type, response_mode, expected",
    [
        ("https://rp.example/cb", "code", None, "https://rp.example/cb?error=x"),
        ("https://rp.example/cb?foo=bar", "code", None, "https://rp.example/cb?foo=bar&error=x"),
        ("https://rp.example/cb", "code", "fragment", "https://rp.example/cb#error=x"),
        ("https://rp.example/cb", "id_token", None, "https://rp.example/cb#error=x"),
        ("https://rp.example/cb?foo=bar", "code token", None, "https://rp.example/cb?foo=bar#error=x"),
    ],
)
def test_add_params_to_authorization_redirect(redirect_uri, response_type, response_mode, expected):
    url = response_modes.add_params_to_authorization_redirect(
        redirect_uri, "error=x", response_type, response_mode
    )
    assert url == expected


@pytest.mark.parametrize(
    "response_type, response_mode, expected",
    [
        ("code", "query", True),
        ("code", "fragment", True),
        # Form Post is permitted for every response type, including the front-channel
        # ones, because the parameters are delivered in a POST body rather than a URL.
        ("code", "form_post", True),
        ("id_token", "fragment", True),
        ("id_token", "query", False),
        ("code token", "query", False),
        ("id_token token", "form_post", True),
        ("code", "not-a-mode", False),
    ],
)
def test_response_mode_permitted(response_type, response_mode, expected):
    assert response_modes.response_mode_permitted(response_type, response_mode) is expected


def test_form_post_disabled_by_setting(oauth2_settings):
    oauth2_settings.FORM_POST_RESPONSE_MODE_ENABLED = False
    assert response_modes.response_mode_permitted("code", "form_post") is False
    oauth2_settings.FORM_POST_RESPONSE_MODE_ENABLED = True
    assert response_modes.response_mode_permitted("code", "form_post") is True


@pytest.mark.parametrize(
    "url, redirect_uri, expected_action, expected_fields",
    [
        (
            "https://rp.example/cb?code=abc&state=x",
            "https://rp.example/cb",
            "https://rp.example/cb",
            [("code", "abc"), ("state", "x")],
        ),
        # A registered URI that already has a query keeps it on the action, while the
        # response parameters become form fields.
        (
            "https://rp.example/cb?foo=bar&code=abc&state=x",
            "https://rp.example/cb?foo=bar",
            "https://rp.example/cb?foo=bar",
            [("code", "abc"), ("state", "x")],
        ),
        # Front-channel responses carry their parameters in the fragment.
        (
            "https://rp.example/cb#access_token=tok&state=s",
            "https://rp.example/cb",
            "https://rp.example/cb",
            [("access_token", "tok"), ("state", "s")],
        ),
        # Without a known redirect URI, the query is treated as the response.
        (
            "https://rp.example/cb?error=access_denied&state=z",
            None,
            "https://rp.example/cb",
            [("error", "access_denied"), ("state", "z")],
        ),
    ],
)
def test_form_post_parameters(url, redirect_uri, expected_action, expected_fields):
    action, fields = response_modes.form_post_parameters(url, redirect_uri)
    assert action == expected_action
    assert fields == expected_fields


def test_form_post_parameters_decodes_special_characters():
    action, fields = response_modes.form_post_parameters(
        "https://rp.example/cb?state=a%20b%26c&error=access_denied",
        "https://rp.example/cb",
    )
    assert action == "https://rp.example/cb"
    assert fields == [("state", "a b&c"), ("error", "access_denied")]
