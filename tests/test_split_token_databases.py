"""Executable evidence for why token models must share one database.

The startup check rejects this configuration, so the tests below call the write paths
directly (bypassing the check on purpose) to pin down *why* the restriction exists. Each
test provisions two throwaway file-backed SQLite aliases and creates the schema
explicitly. ``AccessToken`` is routed to ``split_beta``; the user, application, refresh
token and ID token are routed to ``split_alpha``. The full schema is mirrored on both
aliases because SQLite resolves a foreign-key parent table even with enforcement off, so
a table whose parents exist only on the other alias cannot be created or inserted into
at all. Mirroring is the controlled-routing stand-in: each row still lands only on the
alias the router names.

The failures are deterministic rather than timing-dependent:

* the atomic block around ``save_bearer_token`` is scoped to the AccessToken alias, so
  the refresh token insert runs in a different, independently committed transaction;
* ``RefreshToken.revoke_family`` updates refresh rows in one transaction and deletes
  access rows in another;
* ``validate_refresh_token`` uses ``select_related("access_token")``, one SQL statement
  that cannot join across databases.
"""

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core import checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.db import IntegrityError, connections
from django.db.models.query import QuerySet
from django.test import override_settings
from django.utils import timezone
from oauthlib.common import Request

from oauth2_provider.core.checks import validate_token_configuration
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

ALPHA = "split_alpha"
BETA = "split_beta"
FAMILY_ID = "00000000-0000-0000-0000-000000000001"


def _database_settings(path):
    return {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(path),
        "ATOMIC_REQUESTS": False,
        "AUTOCOMMIT": True,
        "CONN_MAX_AGE": 0,
        "CONN_HEALTH_CHECKS": False,
        "OPTIONS": {},
        "TIME_ZONE": None,
        "USER": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": "",
        "TEST": {"CHARSET": None, "COLLATION": None, "MIGRATE": True, "MIRROR": None, "NAME": None},
    }


@pytest.fixture
def split_token_databases(settings, tmp_path):
    """Two file-backed aliases, with the split token schema and split router."""
    for alias in (ALPHA, BETA):
        connections.databases[alias] = _database_settings(tmp_path / f"{alias}.sqlite3")
        # Instantiate (and cache) the wrapper while the settings entry exists, then drop
        # the entry so Django's test harness treats the alias as dynamically created.
        connections[alias]
        del connections.databases[alias]

    try:
        # Run migrations with no router first: the multi-database settings module
        # installs routers whose allow_migrate would skip these aliases.
        settings.DATABASE_ROUTERS = []
        # Mirror the full schema on both aliases. SQLite resolves a foreign-key parent
        # table even when enforcement is off, so a table whose parents exist only on the
        # other alias cannot be created or inserted into at all; mirroring is the routing
        # stand-in that lets the tests reach the commit-ordering failures below.
        for alias in (ALPHA, BETA):
            call_command("migrate", database=alias, verbosity=0, interactive=False)
        # A relational database cannot enforce an FK whose parent row is on another
        # connection, so a split deployment necessarily runs without cross-database
        # referential integrity. Model that posture.
        for alias in (ALPHA, BETA):
            with connections[alias].cursor() as cursor:
                cursor.execute("PRAGMA foreign_keys = OFF")
        # Applied after the schema exists. The router routes reads to the same aliases as
        # writes, which still leaves the cross-database write windows below.
        settings.DATABASE_ROUTERS = ["tests.db_router.SplitTokenRouter"]
        yield {"alpha": ALPHA, "beta": BETA}
    finally:
        for alias in (ALPHA, BETA):
            connections[alias].close()
            del connections[alias]


@pytest.fixture
def seeded(db, split_token_databases):
    User = get_user_model()
    Application = get_application_model()
    user = User.objects.db_manager(ALPHA).create_user(
        "split-user", "split@example.com", "123456"
    )
    application = Application.objects.using(ALPHA).create(
        client_id="split-client",
        client_secret="split-secret",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
    )
    return user, application


def _request(user, application):
    request = Request("/token/", http_method="POST")
    request.user = user
    request.client = application
    request.refresh_token_instance = None
    return request


def test_startup_check_rejects_split_write_routing():
    with override_settings(DATABASE_ROUTERS=["tests.db_router.SplitTokenRouter"]):
        messages = validate_token_configuration(None)
    assert [message.id for message in messages] == ["oauth2_provider.E009"]
    assert isinstance(messages[0], checks.Error)


def test_startup_check_rejects_read_write_disagreement():
    # The check used to compare db_for_write only. The join, forward FKs and
    # source_refresh_token lookups read the other model through db_for_read.
    with override_settings(DATABASE_ROUTERS=["tests.db_router.SplitTokenReadRouter"]):
        messages = validate_token_configuration(None)
    assert [message.id for message in messages] == ["oauth2_provider.E009"]


def test_manage_check_fails_for_split_configuration():
    with override_settings(DATABASE_ROUTERS=["tests.db_router.SplitTokenRouter"]):
        with pytest.raises(SystemCheckError, match="oauth2_provider.E009"):
            call_command("check")


def test_issuance_can_commit_refresh_without_its_access_token(seeded, split_token_databases):
    """A failure after the alpha insert leaves a refresh token whose access is rolled back.

    ``save_bearer_token`` opens atomic on beta (the AccessToken alias). The refresh
    insert runs on alpha inside that block but in its own autocommit transaction. If it
    succeeds and the surrounding block later fails, beta rolls back the access token and
    alpha keeps the refresh token: an orphan ``validate_refresh_token`` rejects.
    """
    user, application = seeded
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()
    validator = OAuth2Validator()
    request = _request(user, application)

    real_save = RefreshToken.save

    def save_then_fail(instance, *args, **kwargs):
        real_save(instance, *args, **kwargs)
        raise RuntimeError("beta transaction failed after alpha committed")

    token = {"scope": "read", "access_token": "split-access", "refresh_token": "split-refresh"}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(RefreshToken, "save", save_then_fail)
        with pytest.raises(RuntimeError):
            validator.save_bearer_token(token, request)

    assert AccessToken.objects.using(BETA).count() == 0
    assert RefreshToken.objects.using(ALPHA).filter(token="split-refresh").exists()


def test_rotation_revokes_refresh_without_removing_access(seeded, split_token_databases):
    """The old refresh row dies on alpha while the old access row survives on beta.

    Rotation revokes the presented refresh token before minting the successor pair.
    ``RefreshToken.revoke`` opens atomic on beta, but the refresh row lives on alpha, so
    the update commits independently. A failure in the beta block then leaves the refresh
    token revoked while the old access token was rolled back into existence.
    """
    user, application = seeded
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()
    validator = OAuth2Validator()
    old_access = AccessToken.objects.using(BETA).create(
        user=user,
        application=application,
        token="old-access",
        expires=timezone.now() + timedelta(hours=1),
        scope="read",
    )
    old_refresh = RefreshToken.objects.using(ALPHA).create(
        user=user,
        application=application,
        access_token_id=old_access.pk,
        token="old-refresh",
    )
    request = _request(user, application)
    request.refresh_token_instance = old_refresh
    token = {"scope": "read", "access_token": "rotated-access", "refresh_token": "rotated-refresh"}

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            validator,
            "_create_access_token",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("beta failed")),
        )
        with pytest.raises(RuntimeError):
            validator.save_bearer_token(token, request)

    old_refresh.refresh_from_db(using=ALPHA)
    assert old_refresh.revoked is not None
    # The beta atomic rolled the delete back, so the old access token is still usable.
    assert AccessToken.objects.using(BETA).filter(token="old-access").exists()


def test_family_revocation_leaves_access_tokens_usable(seeded, split_token_databases):
    """The family update commits on alpha; the access-token delete rolls back on beta."""
    user, application = seeded
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()
    now = timezone.now()
    access = AccessToken.objects.using(BETA).create(
        user=user,
        application=application,
        token="stolen-access",
        expires=now + timedelta(hours=1),
        scope="read",
    )
    refresh = RefreshToken.objects.using(ALPHA).create(
        user=user,
        application=application,
        access_token_id=access.pk,
        token="family-refresh",
        token_family=FAMILY_ID,
    )

    real_delete = QuerySet.delete

    def fail_access_delete(queryset, *args, **kwargs):
        if queryset.model is AccessToken:
            raise RuntimeError("beta delete failed after alpha committed")
        return real_delete(queryset, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(QuerySet, "delete", fail_access_delete)
        with pytest.raises(RuntimeError):
            RefreshToken.revoke_family(refresh.token_family)

    refresh.refresh_from_db(using=ALPHA)
    assert refresh.revoked is not None
    access.refresh_from_db(using=BETA)
    assert access.is_valid(["read"])


def test_split_requires_disabling_cross_database_foreign_keys(seeded, split_token_databases):
    """Turning FK enforcement back on makes the split insertion fail outright.

    ``AccessToken`` has FKs to Application, User and IDToken, and ``RefreshToken`` points
    back at ``AccessToken``. The fixture mirrors the tables on both aliases so the code
    paths above can run, but a split deployment must also run with referential integrity
    disabled: with enforcement on, beta's FK parents are empty because the live
    Application and User rows are on alpha. The database rejects the access-token insert,
    so the split cannot be made safe by routing alone.
    """
    user, application = seeded
    AccessToken = get_access_token_model()

    with connections[BETA].cursor() as cursor:
        cursor.execute("PRAGMA foreign_keys = ON")

    with pytest.raises(IntegrityError):
        AccessToken.objects.using(BETA).create(
            user=user,
            application=application,
            token="fk-enforced-access",
            expires=timezone.now() + timedelta(hours=1),
            scope="read",
        )


def test_refresh_validation_cannot_join_across_databases(seeded, split_token_databases):
    """``select_related`` is one SQL statement, so the join cannot span two aliases."""
    user, application = seeded
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()
    access = AccessToken.objects.using(BETA).create(
        user=user,
        application=application,
        token="join-access",
        expires=timezone.now() + timedelta(hours=1),
        scope="read",
    )
    RefreshToken.objects.using(ALPHA).create(
        user=user,
        application=application,
        access_token_id=access.pk,
        token="join-refresh",
    )
    validator = OAuth2Validator()

    # The refresh row exists on alpha, but the join is resolved against alpha too. The
    # access row is on beta, so the join cannot see it and a live grant is rejected.
    assert RefreshToken.objects.using(ALPHA).filter(token="join-refresh").exists()
    assert validator.validate_refresh_token("join-refresh", application, _request(user, application)) is False
