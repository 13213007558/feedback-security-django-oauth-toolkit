import json

from django.core.management.base import BaseCommand

from ...models import clear_expired, refresh_token_expire_timedelta


class Command(BaseCommand):
    help = (
        "Delete token data that is no longer needed, in resumable phases. Expired grants, "
        "stored authorization requests, orphaned and idle-expired refresh tokens and "
        "expired access/ID tokens are deleted immediately; revoked refresh tokens are kept "
        "while they can still prove a replay, and deleted once their evidence retention "
        "period has passed. Run it as a cronjob; pass --resume to continue an interrupted "
        "run from its last checkpoint."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--resume",
            action="store_true",
            help=(
                "Continue the most recent interrupted/running cleanup from its last "
                "checkpoint instead of starting a new run. Every phase is idempotent, so "
                "resuming and restarting converge on the same state."
            ),
        )
        parser.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help=(
                "Report format. The report contains only run counts and the non-sensitive "
                "cleanup run id -- never token values, checksums or user identifiers."
            ),
        )

    def handle(self, *args, **options):
        if refresh_token_expire_timedelta() is None:
            self.stderr.write(
                self.style.WARNING(
                    "REFRESH_TOKEN_EXPIRE_SECONDS is not set (or is 0), so refresh tokens never "
                    "age-expire. cleartokens will only remove revoked and orphaned refresh tokens; "
                    "expired access and ID tokens that are still bound to a refresh token are kept "
                    "as long as that refresh token lives. Set REFRESH_TOKEN_EXPIRE_SECONDS to enable "
                    "expiry-based cleanup."
                )
            )
        report = clear_expired(resume=options["resume"])
        if options["format"] == "json":
            self.stdout.write(json.dumps(report.as_dict(), sort_keys=True))
        else:
            self.stdout.write(
                f"cleanup run {report.run_id} {report.status} "
                f"(last phase {report.phase}, {report.batches} batches)"
            )
            for phase, count in report.counts.items():
                self.stdout.write(f"  {phase}: {count} deleted")
