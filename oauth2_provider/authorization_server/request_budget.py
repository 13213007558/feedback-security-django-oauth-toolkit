"""Per-client capacity control for stored authorization requests.

A stored authorization request (see
:mod:`oauth2_provider.authorization_server.stored_requests`) occupies temporary
server storage from when it is pushed until it is consumed or reaped. When the
PAR endpoint (:rfc:`9126`) is open to many clients, one client piling up
requests it never consumes must not be able to fill that storage and starve the
others. This module holds the admission decision, kept independent of the
storage technology so it can be driven by any backend that implements
:class:`PendingRequestStorage`.

Entry states
------------

Every stored entry is in exactly one of three states:

* **unconsumed** — stored, not yet presented at the authorization endpoint;
* **in-progress** — a consumption is under way (the row is locked inside the
  consume transaction) but has not finalized;
* **expired** — past its ``expires`` deadline, awaiting reclamation.

Only *live* entries — unconsumed and in-progress — count against a client's
budget. An in-progress entry still occupies capacity: the storage is not
reclaimed until the consumption finalizes, and the client cannot reclaim the
slot early by starting to consume. Expired entries never count; admission
reclaims them first (:meth:`ClientRequestBudget.admit`), so a client whose
requests lapse unused gets its budget back without waiting for the periodic
``cleartokens`` sweep.

The budget is strictly per client: admission never evicts another client's
entries, so rejecting an over-limit client cannot disturb anyone else's valid
requests.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Protocol

from django.utils import timezone


class RequestBudgetExceeded(Exception):
    """A client's stored-request budget is exhausted; the request must be rejected."""

    def __init__(self, client_id: str, max_pending_per_client: int) -> None:
        super().__init__(
            f"Client {client_id!r} has reached the limit of {max_pending_per_client} "
            "pending stored authorization requests."
        )
        self.client_id = client_id
        self.max_pending_per_client = max_pending_per_client


class PendingRequestStorage(Protocol):
    """The storage operations admission needs, scoped to one client's entries."""

    def reap_expired(self, client_id: str, now: datetime) -> int:
        """Delete the client's expired entries and return how many were removed."""
        ...

    def count_live(self, client_id: str, now: datetime) -> int:
        """Count the client's live entries: unconsumed *and* in-progress."""
        ...


@dataclass
class ClientRequestBudget:
    """Admits stored requests up to ``max_pending_per_client`` live entries per client.

    The clock is injectable (``now``) so tests — and any non-standard
    deployment — control the notion of time used for expiry accounting.
    """

    max_pending_per_client: int
    now: Callable[[], datetime] = field(default=timezone.now)

    def admit(self, client_id: str, storage: PendingRequestStorage) -> None:
        """Reclaim the client's expired entries, then refuse once the budget is full.

        Raises :class:`RequestBudgetExceeded` when the client already has
        ``max_pending_per_client`` live (unconsumed or in-progress) entries.
        Admission is read-only apart from the expiry reclamation: a rejected
        admission changes no other client's state and consumes no budget.
        """
        now = self.now()
        storage.reap_expired(client_id, now)
        if storage.count_live(client_id, now) >= self.max_pending_per_client:
            raise RequestBudgetExceeded(client_id, self.max_pending_per_client)
