"""Unit tests for per-client stored-request capacity control.

The admission logic in :mod:`oauth2_provider.authorization_server.request_budget`
is storage-agnostic, so these tests drive it with a controllable clock and an
in-memory storage stand-in that models the three entry states (unconsumed,
in-progress, expired) and records every storage operation. The Django-backed
integration is covered in ``tests/test_stored_requests.py`` and end to end in
``tests/test_pushed_authorization_request.py``.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as tz

import pytest

from oauth2_provider.authorization_server.request_budget import (
    ClientRequestBudget,
    RequestBudgetExceeded,
)


class FakeClock:
    """A controllable clock: time only moves when the test advances it."""

    def __init__(self, start=None):
        self._now = start or datetime(2026, 1, 1, tzinfo=tz.utc)

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += timedelta(seconds=seconds)


class SaveFailed(Exception):
    """The stand-in's storage layer reports a failed save."""


class AlreadyConsumed(Exception):
    """The stand-in's storage layer reports a repeated consumption."""


@dataclass
class Entry:
    client_id: str
    expires: datetime
    state: str = "unconsumed"  # unconsumed | in-progress


class FakeStorage:
    """In-memory storage stand-in implementing the budget's storage protocol.

    Mirrors the Django store's surface: ``save`` persists an admitted entry,
    ``begin_consume`` moves an entry to in-progress (raising on a repeat, as a
    duplicate consumption must), and ``finish_consume`` removes it. Every
    operation is counted so tests can assert how storage work scales.
    """

    def __init__(self):
        self.entries = {}
        self.op_counts = Counter()
        self.fail_saves = False

    # --- PendingRequestStorage protocol (used by ClientRequestBudget) ---

    def reap_expired(self, client_id, now):
        self.op_counts["reap_expired"] += 1
        expired = [
            uri
            for uri, entry in self.entries.items()
            if entry.client_id == client_id and entry.expires <= now
        ]
        for uri in expired:
            del self.entries[uri]
        return len(expired)

    def count_live(self, client_id, now):
        self.op_counts["count_live"] += 1
        return sum(
            1 for entry in self.entries.values() if entry.client_id == client_id and entry.expires > now
        )

    # --- producer/consumer surface (mirrors the Django store) ---

    def save(self, client_id, request_uri, expires):
        self.op_counts["save"] += 1
        if self.fail_saves:
            raise SaveFailed(request_uri)
        self.entries[request_uri] = Entry(client_id=client_id, expires=expires)

    def begin_consume(self, request_uri):
        self.op_counts["begin_consume"] += 1
        entry = self.entries.get(request_uri)
        if entry is None or entry.state != "unconsumed":
            raise AlreadyConsumed(request_uri)
        entry.state = "in-progress"

    def finish_consume(self, request_uri):
        self.op_counts["finish_consume"] += 1
        del self.entries[request_uri]

    def live_count(self, client_id, now):
        """Live entries for the client, without touching the op counters."""
        return sum(
            1 for entry in self.entries.values() if entry.client_id == client_id and entry.expires > now
        )


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def storage():
    return FakeStorage()


def push(budget, storage, clock, client_id, ttl=60):
    """Store one request the way the PAR endpoint does: admit, then save."""
    budget.admit(client_id, storage)
    request_uri = f"urn:ietf:params:oauth:request_uri:fake-{len(storage.entries)}"
    storage.save(client_id, request_uri, clock() + timedelta(seconds=ttl))
    return request_uri


def test_admission_allowed_up_to_the_budget(clock, storage):
    budget = ClientRequestBudget(2, now=clock)

    push(budget, storage, clock, "client")
    push(budget, storage, clock, "client")
    with pytest.raises(RequestBudgetExceeded):
        push(budget, storage, clock, "client")


def test_expired_entries_are_reclaimed_on_admission(clock, storage):
    budget = ClientRequestBudget(2, now=clock)
    push(budget, storage, clock, "client")
    push(budget, storage, clock, "client")

    clock.advance(61)
    # The two expired entries no longer count: admission reclaims them first.
    push(budget, storage, clock, "client")

    assert storage.live_count("client", clock()) == 1
    assert len(storage.entries) == 1


def test_in_progress_entries_still_occupy_the_budget(clock, storage):
    budget = ClientRequestBudget(1, now=clock)
    request_uri = push(budget, storage, clock, "client")

    storage.begin_consume(request_uri)
    # The consumption has not finalized, so the slot is still occupied.
    with pytest.raises(RequestBudgetExceeded):
        push(budget, storage, clock, "client")

    storage.finish_consume(request_uri)
    push(budget, storage, clock, "client")


def test_duplicate_consumption_fails_and_preserves_accounting(clock, storage):
    budget = ClientRequestBudget(1, now=clock)
    request_uri = push(budget, storage, clock, "client")

    storage.begin_consume(request_uri)
    with pytest.raises(AlreadyConsumed):
        storage.begin_consume(request_uri)
    # The failed repeat changed nothing: the entry is still in-progress and
    # still occupies the budget.
    assert storage.live_count("client", clock()) == 1
    with pytest.raises(RequestBudgetExceeded):
        push(budget, storage, clock, "client")

    storage.finish_consume(request_uri)
    with pytest.raises(AlreadyConsumed):
        storage.begin_consume(request_uri)
    assert storage.live_count("client", clock()) == 0


def test_failed_save_does_not_leak_budget(clock, storage):
    budget = ClientRequestBudget(1, now=clock)
    storage.fail_saves = True
    with pytest.raises(SaveFailed):
        push(budget, storage, clock, "client")

    # Admission is read-only apart from expiry reclamation: the failed save
    # consumed no budget, so a retry once storage recovers succeeds.
    storage.fail_saves = False
    push(budget, storage, clock, "client")
    assert storage.live_count("client", clock()) == 1


def test_rejecting_one_client_never_evicts_another(clock, storage):
    budget = ClientRequestBudget(2, now=clock)
    push(budget, storage, clock, "flooder")
    push(budget, storage, clock, "flooder")
    with pytest.raises(RequestBudgetExceeded):
        push(budget, storage, clock, "flooder")

    # The other client's budget is untouched by the flooder's rejections.
    first = push(budget, storage, clock, "well-behaved")
    second = push(budget, storage, clock, "well-behaved")
    with pytest.raises(RequestBudgetExceeded):
        push(budget, storage, clock, "flooder")

    assert storage.entries[first].state == "unconsumed"
    assert storage.entries[second].state == "unconsumed"
    assert storage.live_count("flooder", clock()) == 2
    assert storage.live_count("well-behaved", clock()) == 2


@pytest.mark.parametrize("request_count", [1, 2, 4, 8, 16])
def test_storage_operations_scale_linearly_with_requests(clock, request_count):
    """Each admitted request costs a constant number of storage operations."""
    storage = FakeStorage()
    budget = ClientRequestBudget(100, now=clock)

    for _ in range(request_count):
        push(budget, storage, clock, "client")

    assert storage.op_counts["reap_expired"] == request_count
    assert storage.op_counts["count_live"] == request_count
    assert storage.op_counts["save"] == request_count
    assert sum(storage.op_counts.values()) == 3 * request_count


def test_rejected_admission_performs_no_save(clock, storage):
    budget = ClientRequestBudget(1, now=clock)
    push(budget, storage, clock, "client")
    saves_before = storage.op_counts["save"]

    with pytest.raises(RequestBudgetExceeded):
        push(budget, storage, clock, "client")

    assert storage.op_counts["save"] == saves_before
    assert len(storage.entries) == 1
