"""Test settings with a custom ``AUTH_USER_MODEL``.

``AUTH_USER_MODEL`` is ``account_app.Account``: a real user-model swap.  The
erasure journal stores the primary key as text (so a UUID PK would work too),
and the project-owned ``AccountProfile`` must still be collected.  The
``SET_NULL`` credential shape that makes a bare ``user.delete()`` unsafe is
reproduced by clearing a token's ``user`` FK directly, which is exactly the
row state a collector leaves behind for a swapped model that does not cascade.
"""

from .settings import *  # noqa: F401, F403
from .settings import INSTALLED_APPS


INSTALLED_APPS = tuple(INSTALLED_APPS) + ("tests.account_app",)

AUTH_USER_MODEL = "account_app.Account"

OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL = "oauth2_provider.AccessToken"
OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL = "oauth2_provider.RefreshToken"
OAUTH2_PROVIDER_GRANT_MODEL = "oauth2_provider.Grant"
OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2_provider.Application"
OAUTH2_PROVIDER_DEVICE_GRANT_MODEL = "oauth2_provider.DeviceGrant"
OAUTH2_PROVIDER_ID_TOKEN_MODEL = "oauth2_provider.IDToken"
