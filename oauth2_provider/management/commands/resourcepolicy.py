"""Audit and migrate stored RFC 8707 resource policies.

Switching to exact matching is safe for newly issued tokens without touching a
single existing row: a blank ``resource_policy`` is version 1, and version 1
keeps working. But an operator who wants the stricter rule to apply to existing
authorizations has to decide, per row, whether that is even possible. This
command does that classification and nothing unsafe:

* ``--audit`` (the default) reports each row's current policy, and flags rows
  that cannot move to exact matching without changing the permission they grant.
* ``--migrate`` rewrites the rows that are safe to move.
* ``--purge-unsafe`` (with ``--migrate``) revokes the rows the audit flags,
  which is the only safe way to stop honoring them.

"Safe to move" is deliberately narrow. A row with no resources is unrestricted:
exact matching would either keep it unrestricted (no security gain) or silently
narrow every request -- so it is not migrated. A row whose resources match only
as prefixes (e.g. ``https://api.example.com/v1`` authorizing ``/v1/users``)
would lose access at those sub-paths, so it is flagged as unsafe, not rewritten.
Only rows whose resource identifiers are already distinct -- one entry, or
several entries that differ by more than a path prefix of each other -- can move
without changing what the token authorizes.
"""

from django.core.management.base import BaseCommand

from oauth2_provider.core.resource_policy import (
    RESOURCE_POLICY_EXACT,
    RESOURCE_POLICY_LEGACY,
)
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
    get_refresh_token_model,
)
from oauth2_provider.resource_server.validators import _parse_and_validate_uri


# Audit outcomes.
OUTCOME_CURRENT = "already-exact"
OUTCOME_MIGRATABLE = "migratable"
OUTCOME_UNRESTRICTED = "unrestricted"
OUTCOME_OVERLAP = "overlapping"
OUTCOME_INVALID = "unmigratable-invalid"


def _path_prefixes(left, right):
    """Whether one parsed resource is a path prefix of the other."""
    left_parts = _parse_and_validate_uri(left)
    right_parts = _parse_and_validate_uri(right)
    if left_parts is None or right_parts is None:
        return False
    left_scheme, left_host, left_port, left_path = left_parts
    right_scheme, right_host, right_port, right_path = right_parts
    if (left_scheme, left_host, left_port) != (right_scheme, right_host, right_port):
        return False
    left_normalized = left_path.rstrip("/") + "/"
    right_normalized = right_path.rstrip("/") + "/"
    return left_normalized.startswith(right_normalized) or right_normalized.startswith(left_normalized)


def classify_resources(resources):
    """Return ``(outcome, detail)`` for moving *resources* from prefix to exact."""
    if not resources:
        return OUTCOME_UNRESTRICTED, "no resource restriction; exact matching changes nothing it grants"

    for resource in resources:
        if _parse_and_validate_uri(resource) is None:
            return OUTCOME_INVALID, f"{resource!r} is not a valid resource identifier"

    for index, left in enumerate(resources):
        for right in resources[index + 1 :]:
            if _path_prefixes(left, right):
                return (
                    OUTCOME_OVERLAP,
                    f"{left!r} and {right!r} overlap as URL prefixes, so exact matching removes "
                    "access that prefix matching granted",
                )

    return OUTCOME_MIGRATABLE, "resource identifiers are already distinct"


class Command(BaseCommand):
    help = (
        "Audit RFC 8707 resource-policy versions on grants, access tokens and refresh "
        "tokens, and move the rows that exact matching cannot narrow."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--audit",
            action="store_true",
            help="Report only, even when --migrate is also given (the default when --migrate is absent).",
        )
        parser.add_argument(
            "--migrate",
            action="store_true",
            help="Move rows that are safe to move to the exact resource policy.",
        )
        parser.add_argument(
            "--purge-unsafe",
            action="store_true",
            help="With --migrate, revoke access tokens and refresh tokens flagged as unsafe "
            "instead of leaving them on the old policy. Grants and access tokens with no "
            "restriction are revoked; refresh tokens are revoked and their access tokens "
            "deleted.",
        )
        parser.add_argument(
            "--policy",
            default=RESOURCE_POLICY_EXACT,
            help="Target policy for --migrate (only 'exact' is accepted).",
        )

    def handle(self, *args, **options):
        if options["policy"] != RESOURCE_POLICY_EXACT:
            self.stderr.write(
                self.style.ERROR(
                    "--policy only accepts 'exact'; moving unrestricted or overlapping rows to "
                    "'prefix' would widen them."
                )
            )
            return

        labelled_models = (
            ("grant", get_grant_model()),
            ("access token", get_access_token_model()),
            ("refresh token", get_refresh_token_model()),
        )

        plan = {label: self._plan(model) for label, model in labelled_models}

        self._report(plan)

        if not options["migrate"] or options["audit"]:
            return

        if options["purge_unsafe"] and not any(
            outcome in (OUTCOME_UNRESTRICTED, OUTCOME_OVERLAP, OUTCOME_INVALID)
            for entries in plan.values()
            for _row, outcome, _detail in entries
        ):
            self.stdout.write("No unsafe rows to purge.")
        elif options["purge_unsafe"]:
            self.stdout.write(
                self.style.WARNING(
                    "Purging unsafe rows revokes long-lived credentials. Back up the token "
                    "tables first if you may need to notify their owners."
                )
            )

        for label, model in labelled_models:
            self._apply(label, model, plan[label], purge_unsafe=options["purge_unsafe"])

    def _plan(self, model):
        rows = model._default_manager.all()
        plan = []
        for row in rows.iterator():
            policy = row.resource_policy or RESOURCE_POLICY_LEGACY
            if policy == RESOURCE_POLICY_EXACT:
                plan.append((row, OUTCOME_CURRENT, "already exact"))
                continue
            outcome, detail = classify_resources(row.resource or [])
            plan.append((row, outcome, detail))
        return plan

    def _report(self, plan):
        total = sum(len(entries) for entries in plan.values())
        self.stdout.write(f"Resource policy audit: {total} row(s)")
        for label, entries in plan.items():
            self.stdout.write(f"{label}: {len(entries)} row(s)")
            for outcome, description in (
                (OUTCOME_CURRENT, "already exact"),
                (OUTCOME_MIGRATABLE, "can move to exact"),
                (OUTCOME_UNRESTRICTED, "unrestricted; cannot be narrowed safely"),
                (OUTCOME_OVERLAP, "overlapping prefixes; cannot be narrowed safely"),
                (OUTCOME_INVALID, "invalid resource; cannot be migrated"),
            ):
                matching = [(row, detail) for row, result, detail in entries if result == outcome]
                if not matching:
                    continue
                self.stdout.write(f"  {len(matching)} {outcome}: {description}")
                if outcome == OUTCOME_CURRENT:
                    continue
                for row, detail in matching:
                    stored = row.resource_policy or RESOURCE_POLICY_LEGACY
                    self.stdout.write(
                        f"    pk={row.pk} stored={stored or RESOURCE_POLICY_LEGACY!r} "
                        f"resource={row.resource!r}: {detail}"
                    )

        unsafe = sum(
            1
            for entries in plan.values()
            for _row, outcome, _detail in entries
            if outcome in (OUTCOME_UNRESTRICTED, OUTCOME_OVERLAP, OUTCOME_INVALID)
        )
        if unsafe:
            self.stdout.write(
                self.style.WARNING(
                    f"{unsafe} row(s) cannot move to exact matching without changing what they "
                    "authorize. Pass --purge-unsafe with --migrate to revoke them, or leave them "
                    "on prefix until they expire."
                )
            )

    def _apply(self, label, model, entries, purge_unsafe):
        migrated = []
        purged = []
        for row, outcome, _detail in entries:
            if outcome == OUTCOME_MIGRATABLE:
                migrated.append(row.pk)
            elif outcome in (OUTCOME_UNRESTRICTED, OUTCOME_OVERLAP, OUTCOME_INVALID) and purge_unsafe:
                purged.append(row.pk)

        if migrated:
            model._default_manager.filter(pk__in=migrated).update(resource_policy=RESOURCE_POLICY_EXACT)
            self.stdout.write(f"{label}: moved {len(migrated)} row(s) to exact")

        if purged:
            self._purge(label, model, purged)

    def _purge(self, label, model, pks):
        if label == "refresh token":
            # Revoke through the model so the bound access token goes with it;
            # a deleted access token with a live refresh token defeats revocation.
            for row in model._default_manager.filter(pk__in=pks):
                row.revoke()
        else:
            model._default_manager.filter(pk__in=pks).delete()
        self.stdout.write(self.style.WARNING(f"{label}: revoked {len(pks)} unsafe row(s)"))
