"""Material retention policy for Workload API outages.

Two caches, two rule sets:

* ``local``     - the SVID we present on new dials. Reuse is bounded by the
                  SVID's own ``notAfter`` minus a safety margin, and by a short
                  post-failure grace window. A stale local SVID makes *our*
                  new dials fail; it cannot make us trust the wrong peer.
* ``federated`` - foreign trust bundles used to verify peers. Reuse is bounded
                  by a *separate* grace window. An observed removal is applied
                  immediately (no grace), because that is an explicit operator
                  decision. A stale federated bundle can make us accept a peer
                  we should no longer trust, which is the more dangerous of the
                  two failure modes.

``BaselinePolicy`` reproduces py-spiffe today: no time checks at all, and the
only stop signal is a non-retryable gRPC code.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Fault(str, Enum):
    NONE = 'none'
    TRANSIENT = 'transient'  # UNAVAILABLE / DEADLINE_EXCEEDED / stream EOF
    PERMANENT_AUTH = 'permanent'  # PERMISSION_DENIED / UNAUTHENTICATED
    STREAM_STOPPED = 'stopped'  # retry_connect=False, or non-retryable code


@dataclass(frozen=True)
class PolicyParams:
    # Local SVID: roughly 2-4 reconnect cycles, far below a typical 1h SVID TTL.
    local_grace: float = 120.0
    # Refuse to dial when fewer than this many seconds of SVID validity remain.
    local_expiry_margin: float = 30.0
    # Federated trust: shorter than local, because accepting a stale root is a
    # trust decision rather than a proof of our own identity.
    federated_grace: float = 60.0
    # Absolute staleness cap, even across repeated short outages.
    federated_max_age: float = 3600.0
    # Time allowed for established connections to drain once new dials stop.
    established_drain: float = 30.0


@dataclass
class Snapshot:
    received_at: float
    not_after: float
    local_domain: str
    federated_domains: frozenset[str]
    serial: int | None = None


@dataclass
class Decision:
    allowed: bool
    reason: str
    remaining: float | None = None


@dataclass
class Evaluation:
    now: float
    local: Decision
    federated: Decision
    established: Decision
    stop_new_dials: bool
    stop_reason: str | None


class BaselinePolicy:
    """py-spiffe as-is: last material is reused forever; only gRPC codes stop it."""

    name = 'current py-spiffe'

    def __init__(self) -> None:
        self.snapshot: Snapshot | None = None
        self.fault = Fault.NONE
        self.fault_at: float | None = None
        self.stopped = False

    def on_update(
        self,
        *,
        now: float,
        not_after: float,
        local_domain: str,
        federated_domains: frozenset[str],
        serial: int | None = None,
    ) -> None:
        self.snapshot = Snapshot(now, not_after, local_domain, federated_domains, serial)
        self.fault = Fault.NONE
        self.fault_at = None

    def on_fault(self, *, now: float, fault: Fault) -> None:
        self.fault = fault
        self.fault_at = now
        if fault is Fault.STREAM_STOPPED:
            # Only CANCELLED/INVALID_ARGUMENT (or retry_connect=False) reach
            # X509Source._on_error. PERMISSION_DENIED is retried forever today.
            self.stopped = True

    def evaluate(self, now: float) -> Evaluation:
        if self.snapshot is None:
            return Evaluation(
                now,
                Decision(False, 'no update yet'),
                Decision(False, 'no update yet'),
                Decision(False, 'not established'),
                True,
                'no material',
            )
        if self.stopped:
            reason = 'source closed by X509Source._on_error'
            return Evaluation(
                now,
                Decision(False, reason),
                Decision(False, reason),
                Decision(True, 'already-established TLS session still works'),
                True,
                reason,
            )
        remaining = self.snapshot.not_after - now
        return Evaluation(
            now,
            Decision(True, 'no expiry check in py-spiffe', remaining),
            Decision(True, 'no bundle-age or removal tracking'),
            Decision(True, 'already-established TLS session still works'),
            False,
            None,
        )


class GuardedPolicy:
    """Recommended policy: separate local and federated retention."""

    name = 'guarded'

    def __init__(self, params: PolicyParams | None = None) -> None:
        self.params = params or PolicyParams()
        self.snapshot: Snapshot | None = None
        self.fault = Fault.NONE
        self.fault_at: float | None = None
        self.last_contact_at: float | None = None
        self.stopped = False
        # First moment new dials became blocked; drives the drain deadline.
        self.stop_since: float | None = None
        # Domains removed by an update, with the time of removal. Kept forever:
        # a removed trust anchor must not come back from an older cached copy.
        self.removed: dict[str, float] = {}

    def on_update(
        self,
        *,
        now: float,
        not_after: float,
        local_domain: str,
        federated_domains: frozenset[str],
        serial: int | None = None,
    ) -> None:
        previous = self.snapshot
        if previous is not None:
            for domain in previous.federated_domains - federated_domains:
                self.removed.setdefault(domain, now)
        self.snapshot = Snapshot(now, not_after, local_domain, federated_domains, serial)
        self.last_contact_at = now
        self.fault = Fault.NONE
        self.fault_at = None
        self.stopped = False
        self.stop_since = None

    def on_fault(self, *, now: float, fault: Fault) -> None:
        if fault is Fault.NONE:
            return
        if self.fault is Fault.NONE:
            self.fault_at = now
        self.fault = fault

    def on_stream_open_without_update(self, *, now: float) -> None:
        # Opening a stream proves the agent is reachable and the workload is
        # still authorized to call the API, but it does not refresh material.
        # Track contact separately from material age.
        self.last_contact_at = now

    def evaluate(self, now: float) -> Evaluation:
        p = self.params
        if self.snapshot is None:
            return Evaluation(
                now,
                Decision(False, 'no update yet'),
                Decision(False, 'no update yet'),
                Decision(False, 'not established'),
                True,
                'no material',
            )
        snap = self.snapshot
        remaining = snap.not_after - now
        outage = 0.0 if self.fault_at is None else max(0.0, now - self.fault_at)
        stop_reason: str | None = None

        # ---- local SVID -------------------------------------------------
        if self.fault is Fault.PERMANENT_AUTH:
            local = Decision(False, 'authorization permanently denied')
            stop_reason = 'permanent authorization error'
        elif remaining <= 0:
            local = Decision(False, 'SVID expired', remaining)
            stop_reason = 'SVID expired'
        elif remaining <= p.local_expiry_margin:
            local = Decision(False, f'only {remaining:.0f}s of SVID validity left', remaining)
            stop_reason = 'SVID inside expiry margin'
        elif outage >= p.local_grace:
            local = Decision(False, f'local grace {p.local_grace:.0f}s exceeded', remaining)
            stop_reason = 'local retention window exceeded'
        else:
            local = Decision(
                True, f'cached SVID, {remaining:.0f}s left, outage {outage:.0f}s', remaining
            )

        # ---- federated bundles -----------------------------------------
        age = now - snap.received_at
        fed_rejected = {d: 'removed by a later update' for d in self.removed}
        if self.fault is Fault.PERMANENT_AUTH:
            federated = Decision(False, 'authorization permanently denied', None)
        elif age > p.federated_max_age:
            federated = Decision(
                False, f'federated material older than {p.federated_max_age:.0f}s', None
            )
            stop_reason = stop_reason or 'federated max age exceeded'
        elif outage >= p.federated_grace:
            federated = Decision(
                False,
                f'federation outage {outage:.0f}s exceeds grace {p.federated_grace:.0f}s',
                None,
            )
            stop_reason = stop_reason or 'federation retention window exceeded'
        elif fed_rejected:
            # A removal narrows *which peers* we trust; it does not invalidate
            # the whole material set. Local-domain dials must keep working.
            remaining_domains = snap.federated_domains - set(fed_rejected)
            federated = Decision(
                True,
                f'trusting {", ".join(sorted(remaining_domains)) or "no federated peers"}; '
                f'rejecting {", ".join(sorted(fed_rejected))}',
                None,
            )
        else:
            federated = Decision(
                True,
                f'{len(snap.federated_domains)} federated domain(s), age {age:.0f}s',
                None,
            )

        stop_new_dials = (not local.allowed) or (not federated.allowed)
        if stop_new_dials and stop_reason is None:
            stop_reason = 'no usable trust material'
        if stop_new_dials and self.stop_since is None:
            self.stop_since = now
        elif not stop_new_dials:
            self.stop_since = None

        # ---- already-established connections ---------------------------
        # TLS does not revalidate on application data. The only lever is to
        # close them; draining starts when new dials stop.
        if stop_new_dials:
            anchor = self.stop_since if self.stop_since is not None else now
            draining = (now - anchor) < p.established_drain
            established = Decision(
                draining,
                f'drain deadline {p.established_drain:.0f}s after stop',
            )
            if not draining:
                stop_reason = stop_reason or 'established-connection drain deadline reached'
        else:
            established = Decision(True, 'continue; TLS does not revalidate on data')

        return Evaluation(now, local, federated, established, stop_new_dials, stop_reason)

    def federated_domains_for_new_handshake(self) -> frozenset[str]:
        if self.snapshot is None:
            return frozenset()
        return self.snapshot.federated_domains - set(self.removed)
