"""Staged, resumable refresh-token cleanup and its interaction with revocation evidence.

The acceptance criteria are exercised here with a frozen clock:

* immediate data is deleted;
* records still needed to decide a refresh-token replay are kept even though they are
  old, and are deleted only once their evidence retention period has passed;
* a cleanup interrupted mid-run and restarted reaches the same state, and an old
  credential never becomes usable again;
* the report carries counts and the run id only;
* deleting an account can keep minimal, non-credential evidence.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command

from oauth2_provider.models import (
    CLEANUP_PHASE_EXPIRED_ACCESS_TOKENS,
    CLEANUP_PHASE_EXPIRED_GRANTS,
    CLEANUP_PHASE_EXPIRED_REVOCATION_EVIDENCE,
    CLEANUP_PHASE_REVOKED_REFRESH_TOKENS,
    CLEANUP_PHASES,
    AccessToken,
    Application,
    Grant,
    RefreshToken,
    RevokedTokenEvidence,
    TokenCleanupRun,
    clear_expired,
    purge_user_credentials,
    refresh_token_evidence_retention_timedelta,
    revoked_refresh_token_retention,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from .common_testing import OAuth2ProviderTestCase as TestCase


UserModel = get_user_model()

FROZEN_NOW = datetime(2026, 11, 12, 12, 0, 0, tzinfo=dt_timezone.utc)


def _checksum(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.mark.usefixtures("oauth2_settings")
class CleanupTestCase(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("cleanup-user", "cleanup@example.com", "123456")
        self.application = Application.objects.create(
            name="cleanup-app",
            redirect_uris="https://example.com/callback",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_SIZE = 2
        self.oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = 0.0

    def _refresh_token(self, value, *, revoked=None, family=None, access_token=None, user=None):
        if access_token is None and revoked is None:
            access_token = AccessToken.objects.create(
                user=user or self.user,
                token=f"access-for-{value}",
                application=self.application,
                expires=FROZEN_NOW - timedelta(days=1),
            )
        return RefreshToken.objects.create(
            user=user or self.user,
            token=value,
            application=self.application,
            access_token=access_token,
            revoked=revoked,
            token_family=family,
        )


@pytest.mark.usefixtures("oauth2_settings")
class TestEvidenceRetentionPolicy(CleanupTestCase):
    def test_retention_is_never_shorter_than_the_enabled_protection(self):
        # Reuse protection needs revoked rows for the refresh-token lifetime, even when the
        # grace period is zero and the evidence setting is unset.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 3600
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 0
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = None
        assert revoked_refresh_token_retention() == timedelta(seconds=3600)

    def test_explicit_evidence_retention_extends_the_floor(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 60
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 7 * 24 * 3600
        assert revoked_refresh_token_retention() == timedelta(seconds=7 * 24 * 3600)

    def test_explicit_evidence_retention_cannot_shorten_required_evidence(self):
        # A too-short explicit value must not weaken reuse detection.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 86400
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 60
        assert revoked_refresh_token_retention() == timedelta(seconds=86400)

    def test_grace_period_alone_retains_evidence_without_reuse_protection(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = False
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 120
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = None
        assert revoked_refresh_token_retention() == timedelta(seconds=120)

    def test_explicit_retention_bounds_evidence_without_reuse_protection(self):
        # With reuse protection off, a revoked row backs no live security decision, so an
        # explicit retention is a privacy cap. It must not cut into the grace window.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = False
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 120
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 30 * 24 * 3600
        assert revoked_refresh_token_retention() == timedelta(seconds=30 * 24 * 3600)
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 10
        assert revoked_refresh_token_retention() == timedelta(seconds=120)

    def test_retention_is_null_when_evidence_must_be_kept_forever(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = None
        assert revoked_refresh_token_retention() is None

    def test_invalid_evidence_value_raises(self):
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = "week"
        with pytest.raises(Exception, match="REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS"):
            refresh_token_evidence_retention_timedelta()


@pytest.mark.usefixtures("oauth2_settings")
class TestFrozenTimeBoundaries(CleanupTestCase):
    def test_revoked_token_at_the_retention_boundary_is_deleted(self):
        # Exactly at ``revoked + retention`` the evidence deadline has passed (``<=``),
        # matching the rest of the toolkit's expiry comparisons.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = False
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 3600
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 86400
        retention = revoked_refresh_token_retention()
        at_boundary = self._refresh_token(
            "boundary-revoked", revoked=FROZEN_NOW - retention, family=uuid.uuid4()
        )
        inside = self._refresh_token(
            "inside-revoked",
            revoked=FROZEN_NOW - retention + timedelta(seconds=1),
            family=uuid.uuid4(),
        )

        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            clear_expired()

        assert not RefreshToken.objects.filter(pk=at_boundary.pk).exists()
        assert RefreshToken.objects.filter(pk=inside.pk).exists()
        assert RefreshToken.objects.filter(pk=inside.pk).get().revoked is not None

    def test_evidence_row_at_retain_until_boundary_is_deleted(self):
        expired = RevokedTokenEvidence.objects.create(
            token_checksum=_checksum("evidence-expired"),
            token_family=uuid.uuid4(),
            client_id=self.application.client_id,
            revoked_at=FROZEN_NOW - timedelta(days=10),
            retain_until=FROZEN_NOW,
        )
        fresh = RevokedTokenEvidence.objects.create(
            token_checksum=_checksum("evidence-fresh"),
            token_family=uuid.uuid4(),
            client_id=self.application.client_id,
            revoked_at=FROZEN_NOW,
            retain_until=FROZEN_NOW + timedelta(seconds=1),
        )
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            report = clear_expired()
        assert not RevokedTokenEvidence.objects.filter(pk=expired.pk).exists()
        assert RevokedTokenEvidence.objects.filter(pk=fresh.pk).exists()
        assert report.counts[CLEANUP_PHASE_EXPIRED_REVOCATION_EVIDENCE] == 1

    def test_infinite_evidence_retention_keeps_revoked_tokens(self):
        # Reuse protection on, no refresh-token lifetime, no explicit retention: keeping the
        # evidence forever is the only setting that can still detect a replay.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = None
        old = self._refresh_token(
            "forever-revoked", revoked=FROZEN_NOW - timedelta(days=3650), family=uuid.uuid4()
        )
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            report = clear_expired()
        assert RefreshToken.objects.filter(pk=old.pk).exists()
        assert report.counts[CLEANUP_PHASE_REVOKED_REFRESH_TOKENS] == 0


@pytest.mark.usefixtures("oauth2_settings")
class TestImmediateDataIsDeleted(CleanupTestCase):
    def test_expired_grants_orphans_and_bindable_access_tokens(self):
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 3600
        Grant.objects.create(
            user=self.user,
            application=self.application,
            code="expired-code",
            expires=FROZEN_NOW - timedelta(seconds=1),
            redirect_uri="https://example.com/callback",
        )
        orphan = self._refresh_token("orphan", access_token=None)

        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            report = clear_expired()

        assert not Grant.objects.filter(code="expired-code").exists()
        assert not RefreshToken.objects.filter(pk=orphan.pk).exists()
        assert report.counts[CLEANUP_PHASE_EXPIRED_GRANTS] == 1
        assert report.batches >= 1


@pytest.mark.usefixtures("oauth2_settings")
class TestInterruptedRunResumes(CleanupTestCase):
    def _rows(self):
        # One unit in each of several phases, all due at FROZEN_NOW.
        grant = Grant.objects.create(
            user=self.user,
            application=self.application,
            code="resume-code",
            expires=FROZEN_NOW - timedelta(seconds=1),
            redirect_uri="https://example.com/callback",
        )
        # Expired well past the idle cutoff below, so both the refresh token (by the
        # idle join) and the access token (once the refresh token is gone) are due.
        obsolete_access = AccessToken.objects.create(
            user=self.user,
            token="obsolete-access",
            application=self.application,
            expires=FROZEN_NOW - timedelta(days=1),
        )
        expired_refresh = self._refresh_token(
            "expired-refresh", access_token=obsolete_access, family=uuid.uuid4()
        )
        return grant, obsolete_access, expired_refresh

    def test_interrupted_cleanup_resumes_without_resurrecting_a_credential(self):
        grant, obsolete_access, expired_refresh = self._rows()
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 3600
        real_phase = __import__("oauth2_provider.models", fromlist=["_run_cleanup_phase"])._run_cleanup_phase

        calls = {"n": 0}

        def interrupt_after_grants(*args, **kwargs):
            result = real_phase(*args, **kwargs)
            calls["n"] += 1
            if calls["n"] == 1:
                raise KeyboardInterrupt
            return result

        run = TokenCleanupRun.objects.create(status=TokenCleanupRun.RUNNING, counts={})
        with (
            mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW),
            mock.patch("oauth2_provider.models._run_cleanup_phase", side_effect=interrupt_after_grants),
            pytest.raises(KeyboardInterrupt),
        ):
            clear_expired(resume=True)

        run.refresh_from_db()
        # Interrupted mid-phase: the phase is still marked running, and the row it had
        # already deleted stays deleted (deletion is committed per batch).
        assert run.status == TokenCleanupRun.INTERRUPTED
        assert run.phase == CLEANUP_PHASE_EXPIRED_GRANTS
        assert run.counts[CLEANUP_PHASE_EXPIRED_GRANTS] == 1
        assert Grant.objects.filter(pk=grant.pk).exists() is False

        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            report = clear_expired(resume=True)

        assert report.status == TokenCleanupRun.COMPLETED
        assert report.run_id == run.pk
        assert RefreshToken.objects.filter(pk=expired_refresh.pk).exists() is False
        assert AccessToken.objects.filter(pk=obsolete_access.pk).exists() is False
        # The credential the interrupted sweep deleted stays unusable after the restart:
        # a presentation of it is simply an unknown token.
        validator = OAuth2Validator()
        assert not validator.validate_refresh_token("expired-refresh", self.application, mock.MagicMock())
        # A resumed run does not double-count the phase it already completed.
        assert report.counts[CLEANUP_PHASE_EXPIRED_GRANTS] == 1

    def test_restart_without_resume_starts_a_new_run(self):
        TokenCleanupRun.objects.create(status=TokenCleanupRun.RUNNING, counts={})
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            report = clear_expired()
        assert report.run_id == TokenCleanupRun.objects.order_by("-id").first().pk
        assert TokenCleanupRun.objects.filter(status=TokenCleanupRun.RUNNING).count() == 0
        assert report.counts[CLEANUP_PHASE_REVOKED_REFRESH_TOKENS] == 0


@pytest.mark.usefixtures("oauth2_settings")
class TestReportIsNonSensitive(CleanupTestCase):
    def test_report_and_json_contain_only_counts_and_the_run_id(self):
        token_value = "super-secret-refresh-token-value"
        # A token that is due for deletion, so its value is definitely swept.
        self._refresh_token(
            token_value,
            revoked=FROZEN_NOW - timedelta(days=400),
            family=uuid.uuid4(),
            access_token=None,
        )
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 0
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            report = clear_expired()

        payload = json.dumps(report.as_dict())
        assert token_value not in payload
        assert _checksum(token_value) not in payload
        assert self.user.username not in payload
        assert "cleanup@example.com" not in payload
        assert set(report.counts) == set(CLEANUP_PHASES)
        assert set(report.as_dict()) == {"run_id", "status", "phase", "batches", "counts", "cutoffs"}

    def test_command_reports_json(self):
        from io import StringIO

        stdout = StringIO()
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            call_command("cleartokens", "--format=json", stdout=stdout)
        payload = json.loads(stdout.getvalue())
        assert set(payload) == {"run_id", "status", "phase", "batches", "counts", "cutoffs"}
        assert set(payload["counts"]) == set(CLEANUP_PHASES)

    def test_command_text_report_names_phases_but_no_values(self):
        from io import StringIO

        token_value = "text-report-secret"
        self._refresh_token(token_value, revoked=FROZEN_NOW - timedelta(days=400), family=uuid.uuid4())
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 0
        stdout = StringIO()
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            call_command("cleartokens", stdout=stdout)
        output = stdout.getvalue()
        assert "cleanup run" in output
        assert CLEANUP_PHASE_EXPIRED_ACCESS_TOKENS in output
        assert token_value not in output
        assert _checksum(token_value) not in output


@pytest.mark.usefixtures("oauth2_settings")
class TestAccountDeletionCoexistence(CleanupTestCase):
    def test_purge_deletes_credentials_and_keeps_minimal_evidence(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = 3600
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 30 * 24 * 3600
        family = uuid.uuid4()
        self._refresh_token("live-token", family=family)
        revoked_value = "revoked-token"
        self._refresh_token(
            revoked_value,
            revoked=FROZEN_NOW - timedelta(days=1),
            family=family,
            access_token=None,
        )
        assert RefreshToken.objects.filter(user=self.user).count() == 2

        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            counts = purge_user_credentials(self.user)

        assert not RefreshToken.objects.filter(user=self.user).exists()
        assert not AccessToken.objects.filter(user=self.user).exists()
        assert counts["revoked_evidence_created"] == 1

        evidence = RevokedTokenEvidence.objects.get(token_checksum=_checksum(revoked_value))
        # Only non-credential identifiers: no raw token, no user link, no application FK.
        assert revoked_value not in str(evidence.__dict__)
        assert evidence.token_family == family
        assert evidence.retain_until == FROZEN_NOW - timedelta(days=1) + timedelta(days=30)
        assert not RevokedTokenEvidence.objects.filter(token_checksum=_checksum("live-token")).exists()

        # The account is now gone. Replaying the purged revoked token must not be honored;
        # with reuse protection it takes the surviving family down.
        validator = OAuth2Validator()
        assert not validator.validate_refresh_token(revoked_value, self.application, mock.MagicMock())
        assert not RefreshToken.objects.filter(token_family=family, revoked__isnull=True).exists()

    def test_purge_without_reuse_protection_keeps_no_evidence(self):
        # A revoked row only backs reuse detection. Without it, the account deletion has no
        # security reason to retain personal data.
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = False
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 3600
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 30 * 24 * 3600
        self._refresh_token("no-evidence", revoked=FROZEN_NOW - timedelta(days=1), access_token=None)
        counts = purge_user_credentials(self.user)
        assert counts["revoked_evidence_created"] == 0
        assert not RevokedTokenEvidence.objects.filter(token_checksum=_checksum("no-evidence")).exists()

    def test_purge_keeps_evidence_forever_when_retention_is_null(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = True
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = None
        self._refresh_token("forever-evidence", revoked=FROZEN_NOW, family=uuid.uuid4(), access_token=None)
        with mock.patch("oauth2_provider.models.timezone.now", return_value=FROZEN_NOW):
            counts = purge_user_credentials(self.user)
        evidence = RevokedTokenEvidence.objects.get(token_checksum=_checksum("forever-evidence"))
        assert evidence.retain_until is None
        assert counts["revoked_evidence_created"] == 1

    def test_every_credential_is_gone_and_unusable_after_purge(self):
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = 3600
        live_value = "live-after-purge"
        self._refresh_token(live_value, family=uuid.uuid4())
        purge_user_credentials(self.user)
        assert not RefreshToken.objects.filter(token_checksum=_checksum(live_value)).exists()
        validator = OAuth2Validator()
        assert not validator.validate_refresh_token(live_value, self.application, mock.MagicMock())


@pytest.mark.usefixtures("oauth2_settings")
class TestLegacyBehaviorPreserved(CleanupTestCase):
    def test_no_evidence_policy_and_no_reuse_protection_matches_old_grace_only_behavior(self):
        self.oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION = False
        self.oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 1000
        self.oauth2_settings.REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS = None
        self.oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS = None
        assert revoked_refresh_token_retention() == timedelta(seconds=1000)
        assert clear_expired is not None
