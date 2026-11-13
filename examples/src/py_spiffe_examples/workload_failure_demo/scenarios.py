"""Four runnable failure timelines.

Virtual time keeps the demo deterministic: every scenario is a function of
scripted Workload API events, and each checkpoint evaluates both the current
py-spiffe behaviour and the recommended retention policy. TLS verdicts are real
pyOpenSSL handshakes (memory BIOs, no listening ports).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Iterable

import grpc

from . import materials as mat
from .fault_api import Event, Message, Timeline, schedule, simulate
from .trust_store import probe_removal
from spiffe.workloadapi.workload_api_client import RetryPolicy

from .policy import (
    BaselinePolicy,
    Decision,
    Evaluation,
    Fault,
    GuardedPolicy,
    PolicyParams,
)

UTC = dt.timezone.utc


@dataclass
class Checkpoint:
    at: float
    label: str
    baseline: Evaluation
    guarded: Evaluation
    tls: list[dict[str, object]] = field(default_factory=list)


@dataclass
class Scenario:
    key: str
    title: str
    question: str
    timeline: Timeline
    checkpoints: list[Checkpoint]
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            'key': self.key,
            'title': self.title,
            'question': self.question,
            'attempts': [
                {'at': a.at, 'outcome': a.outcome, 'code': a.code, 'backoff': a.backoff}
                for a in self.timeline.attempts
            ],
            'updates': [
                {'at': at, 'serial': m.svid_serial} for at, m in self.timeline.updates
            ],
            'stopped_at': self.timeline.stopped_at,
            'stop_reason': self.timeline.stop_reason,
            'checkpoints': [
                {
                    'at': c.at,
                    'label': c.label,
                    'baseline': _eval_dict(c.baseline),
                    'guarded': _eval_dict(c.guarded),
                    'tls': c.tls,
                }
                for c in self.checkpoints
            ],
            'notes': self.notes,
        }


def _decision(d: Decision) -> dict[str, object]:
    return {'allowed': d.allowed, 'reason': d.reason, 'remaining': d.remaining}


def _eval_dict(e: Evaluation) -> dict[str, object]:
    return {
        'now': e.now,
        'local': _decision(e.local),
        'federated': _decision(e.federated),
        'established': _decision(e.established),
        'stop_new_dials': e.stop_new_dials,
        'stop_reason': e.stop_reason,
    }


class World:
    def __init__(self) -> None:
        self.local_ca = mat.make_authority('local-root', valid_for=dt.timedelta(days=365))
        self.foreign_ca = mat.make_authority('foreign-root', valid_for=dt.timedelta(days=365))
        self.other_ca = mat.make_authority('other-root', valid_for=dt.timedelta(days=365))
        self.client = mat.make_identity('client', 'spiffe://local.test/client', self.local_ca)
        self.server = mat.make_identity(
            'server', 'spiffe://local.test/server', self.local_ca, server=True
        )
        self.other_server = mat.make_identity(
            'other-server', 'spiffe://other.test/server', self.other_ca, server=True
        )
        self.foreign_server = mat.make_identity(
            'foreign-server', 'spiffe://foreign.test/server', self.foreign_ca, server=True
        )
        # Pre-established connection used for the "old connection" boundary.
        self._old_client_ctx = mat.client_context(
            self.client, [self.local_ca, self.foreign_ca, self.other_ca]
        )
        self._old_server_ctx = mat.server_context(self.server, [self.local_ca])
        self.old_client, self.old_server = mat.connect(
            self._old_client_ctx, self._old_server_ctx
        )

    def close(self) -> None:
        mat.close_connections(self.old_client, self.old_server)


def _message(
    serial: int,
    *,
    not_after: float | None = None,
    federated: Iterable[str] = ('foreign.test', 'other.test'),
) -> Message:
    return Message(
        label=f'svid-{serial}',
        not_after=not_after,
        federated_domains=tuple(federated),
        svid_serial=serial,
    )


def _make_policies(start: Message) -> tuple[BaselinePolicy, GuardedPolicy]:
    baseline = BaselinePolicy()
    guarded = GuardedPolicy(PolicyParams())
    for policy in (baseline, guarded):
        policy.on_update(
            now=0.0,
            not_after=start.not_after if start.not_after is not None else 3600.0,
            local_domain='local.test',
            federated_domains=frozenset(start.federated_domains),
            serial=start.svid_serial,
        )
    return baseline, guarded


def _advance(policies, start: float, end: float, step: float = 1.0) -> None:
    """Ticks policies through the interval so drain deadlines are time-accurate."""
    now = start
    while now < end:
        now = min(now + step, end)
        for policy in policies:
            policy.evaluate(now)  # type: ignore[attr-defined]


def _tls_local(
    world: World,
    *,
    identity: mat.Identity | None = None,
    trusted_at: dt.datetime | None = None,
    trusted: Iterable[mat.TrustLike] | None = None,
) -> dict[str, object]:
    anchors = (
        list(trusted)
        if trusted is not None
        else [world.local_ca, world.foreign_ca, world.other_ca]
    )
    identity = identity if identity is not None else world.client
    try:
        mat.handshake(
            identity,
            world.server,
            client_trust=anchors,
            server_trust=[world.local_ca],
            trusted_at=trusted_at,
        )
        return {'label': 'new mTLS dial with cached local SVID', 'ok': True, 'detail': ''}
    except Exception as err:  # noqa: BLE001 - report the real OpenSSL reason
        return {
            'label': 'new mTLS dial with cached local SVID',
            'ok': False,
            'detail': str(err),
        }


def _old_connection(world: World) -> dict[str, object]:
    try:
        mat.exchange(world.old_client, world.old_server, b'still-alive')
        return {
            'label': 'pre-existing TLS connection',
            'ok': True,
            'detail': 'application data still flows',
        }
    except Exception as err:  # noqa: BLE001
        return {
            'label': 'pre-existing TLS connection',
            'ok': False,
            'detail': str(err),
        }


def scenario_transient(world: World) -> Scenario:
    start = _message(1)
    events = [
        Event(0, 'update', message=start),
        Event(10, 'error', code=grpc.StatusCode.UNAVAILABLE),
        Event(10.3, 'error', code=grpc.StatusCode.UNAVAILABLE),
        Event(30, 'update', message=_message(2)),
    ]
    timeline = simulate(events)
    baseline, guarded = _make_policies(start)
    for policy in (baseline, guarded):
        policy.on_fault(now=10, fault=Fault.TRANSIENT)
    _advance((baseline, guarded), 0, 12)

    cp_recovering = Checkpoint(
        at=12,
        label='during outage (2 failed attempts, backoff running)',
        baseline=baseline.evaluate(12),
        guarded=guarded.evaluate(12),
        tls=[_tls_local(world), _old_connection(world)],
    )
    # Recovery arrives at t=30, then attempts reset.
    for policy in (baseline, guarded):
        policy.on_update(
            now=30,
            not_after=3600,
            local_domain='local.test',
            federated_domains=frozenset(start.federated_domains),
            serial=2,
        )
    _advance((baseline, guarded), 30, 31)
    cp_recovered = Checkpoint(
        at=31,
        label='recovered (update delivered, retry counter reset)',
        baseline=baseline.evaluate(31),
        guarded=guarded.evaluate(31),
        tls=[_tls_local(world, identity=_rotated(world)), _old_connection(world)],
    )
    return Scenario(
        'transient',
        'Transient network error (UNAVAILABLE)',
        'Should the backend stop dialing during a short agent outage?',
        timeline,
        [cp_recovering, cp_recovered],
        notes=[
            f'backoff sequence from RetryHandler: {schedule(timeline.policy, 5)}',
            'recovery condition: any valid update; it resets the retry counter and both caches',
        ],
    )


def _rotated(world: World) -> mat.Identity:
    return mat.make_identity('client', 'spiffe://local.test/client', world.local_ca)


def scenario_permanent_auth(world: World) -> Scenario:
    start = _message(1)
    # Current state machine retries PERMISSION_DENIED forever; show a 60s slice
    # where each server attempt happens exactly when the client retries.
    failure_times = [10.0]
    for backoff in schedule(RetryPolicy(), 12):
        failure_times.append(failure_times[-1] + backoff)
        if failure_times[-1] > 60:
            break
    timeline = simulate(
        [Event(0, 'update', message=start)]
        + [Event(at, 'error', code=grpc.StatusCode.PERMISSION_DENIED) for at in failure_times],
        horizon=60,
    )
    baseline, guarded = _make_policies(start)
    # py-spiffe retries PERMISSION_DENIED (it is not in _NON_RETRYABLE_CODES);
    # the recommended policy treats it as permanent.
    baseline.on_fault(now=10, fault=Fault.TRANSIENT)
    guarded.on_fault(now=10, fault=Fault.PERMANENT_AUTH)
    _advance((baseline, guarded), 0, 11)

    cp_immediate = Checkpoint(
        at=11,
        label='immediately after PERMISSION_DENIED',
        baseline=baseline.evaluate(11),
        guarded=guarded.evaluate(11),
        tls=[_tls_local(world), _old_connection(world)],
    )
    _advance((baseline, guarded), 11, 90)
    cp_after = Checkpoint(
        at=90,
        label='90s later, still denied',
        baseline=baseline.evaluate(90),
        guarded=guarded.evaluate(90),
        tls=[_tls_local(world), _old_connection(world)],
    )
    return Scenario(
        'permanent_auth',
        'Permanent authorization error (PERMISSION_DENIED)',
        'Does a revoked workload registration stop new mTLS immediately?',
        timeline,
        [cp_immediate, cp_after],
        notes=[
            'PERMISSION_DENIED is NOT in _NON_RETRYABLE_CODES, so py-spiffe retries at the 5s cap',
            'X509Source stays open and keeps serving the last context to new dials',
            'recommended: stop new dials immediately, drain established connections for a bounded interval',
        ],
    )


def scenario_expiry(world: World) -> Scenario:
    # Local SVID has 60s of validity; outage starts at 5s and never recovers.
    start = _message(1, not_after=60.0)
    timeline = simulate(
        [
            Event(0, 'update', message=start),
            Event(5, 'error', code=grpc.StatusCode.UNAVAILABLE),
        ]
    )
    baseline, guarded = _make_policies(start)
    for policy in (baseline, guarded):
        policy.on_fault(now=5, fault=Fault.TRANSIENT)
    _advance((baseline, guarded), 0, 25)

    short = mat.make_identity(
        'client',
        'spiffe://local.test/client',
        world.local_ca,
        valid_for=dt.timedelta(seconds=60),
    )
    cp_ok = Checkpoint(
        at=25,
        label='35s of validity left',
        baseline=baseline.evaluate(25),
        guarded=guarded.evaluate(25),
        tls=[_tls_local(world, identity=short), _old_connection(world)],
    )
    expired_at = dt.datetime.now(UTC) + dt.timedelta(seconds=61)
    _advance((baseline, guarded), 25, 61)
    cp_expired = Checkpoint(
        at=61,
        label='1s past notAfter (wall clock advanced for verification)',
        baseline=baseline.evaluate(61),
        guarded=guarded.evaluate(61),
        tls=[_tls_local(world, identity=short, trusted_at=expired_at), _old_connection(world)],
    )
    return Scenario(
        'expiry',
        'Local SVID reaches notAfter during an outage',
        'Does the cached SVID remain usable after it expires?',
        timeline,
        [cp_ok, cp_expired],
        notes=[
            'py-spiffe parses but never schedules on notAfter; X509Context has no freshness check',
            'OpenSSL rejects the expired certificate at handshake, not at decision time',
            'recommended: refuse new dials at notAfter - local_expiry_margin (default 30s)',
        ],
    )


def scenario_trust_removal(world: World) -> Scenario:
    start = _message(1, federated=('foreign.test', 'other.test'))
    timeline = simulate(
        [
            Event(0, 'update', message=start),
            # Operator removes other.test from the federation, then the agent goes away.
            Event(10, 'update', message=_message(2, federated=('foreign.test',))),
            Event(20, 'error', code=grpc.StatusCode.UNAVAILABLE),
            Event(120, 'update', message=_message(3, federated=('foreign.test',))),
        ]
    )
    baseline, guarded = _make_policies(start)
    # Baseline has no removal tracking: later updates replace its context wholesale,
    # but spiffetls._on_source_update only ADDS certificates to the live store.
    for policy in (baseline, guarded):
        policy.on_update(
            now=10,
            not_after=3600,
            local_domain='local.test',
            federated_domains=frozenset({'foreign.test'}),
            serial=2,
        )
        policy.on_fault(now=20, fault=Fault.TRANSIENT)
    _advance((baseline, guarded), 0, 30)

    cp_removed = Checkpoint(
        at=30,
        label='other.test removed 20s ago, then UNAVAILABLE',
        baseline=baseline.evaluate(30),
        guarded=guarded.evaluate(30),
        tls=[*_trust_probe(world), _old_connection(world)],
    )
    for policy in (baseline, guarded):
        policy.on_update(
            now=120,
            not_after=3600,
            local_domain='local.test',
            federated_domains=frozenset({'foreign.test'}),
            serial=3,
        )
    _advance((baseline, guarded), 30, 121)
    cp_recovered = Checkpoint(
        at=121,
        label='agent returns 101s later',
        baseline=baseline.evaluate(121),
        guarded=guarded.evaluate(121),
        tls=[*_trust_probe(world), _old_connection(world)],
    )
    return Scenario(
        'trust_removal',
        'Federated trust root removed, then disconnect',
        'Does a removed federated root stop being trusted on new handshakes?',
        timeline,
        [cp_removed, cp_recovered],
        notes=[
            'X509Source drops other.test, but spiffetls context._on_source_update only calls cert_store.add_cert',
            'an existing SSL.Context therefore keeps trusting the removed root',
            'recommended: apply removals immediately, keep a tombstone, and rebuild the SSL.Context',
        ],
    )


def _trust_probe(world: World) -> list[dict[str, object]]:
    result = probe_removal(
        client_identity=world.client,
        server_identity=world.other_server,
        local_ca=world.local_ca,
        removed_ca=world.other_ca,
        kept_ca=world.foreign_ca,
        kept_peer=world.foreign_server,
    )
    checks = [
        result['before'],
        result['after_same_unused_context'],
        result['after_fresh_context'],
        result['after_used_context'],
    ]
    kept = result.get('after_fresh_kept_peer')
    if kept is not None:
        checks.append(kept)
    error = result.get('used_context_update_error')
    if error:
        checks.append(
            {
                'label': 'subscriber callback on a used SSL.Context',
                'ok': False,
                'detail': str(error),
            }
        )
    return checks  # type: ignore[return-value]


def run_all() -> list[Scenario]:
    world = World()
    try:
        return [
            scenario_transient(world),
            scenario_permanent_auth(world),
            scenario_expiry(world),
            scenario_trust_removal(world),
        ]
    finally:
        world.close()
