"""Tests for the Workload API failure demo (no sockets, no SPIRE)."""

from __future__ import annotations

import datetime as dt

import grpc
from py_spiffe_examples.workload_failure_demo import materials as mat
from py_spiffe_examples.workload_failure_demo.fault_api import (
    Event,
    Message,
    schedule,
    simulate,
)
from py_spiffe_examples.workload_failure_demo.policy import (
    BaselinePolicy,
    Fault,
    GuardedPolicy,
    PolicyParams,
)
from py_spiffe_examples.workload_failure_demo.scenarios import run_all
from py_spiffe_examples.workload_failure_demo.trust_store import probe_removal
from spiffe.workloadapi.workload_api_client import (
    _NON_RETRYABLE_CODES,
    RetryPolicy,
)

UTC = dt.timezone.utc


def _tick(policy, start: float, end: float, step: float = 1.0) -> None:
    now = start
    while now < end:
        now = min(now + step, end)
        policy.evaluate(now)


def test_permission_denied_is_not_classified_permanent_by_current_state_machine() -> None:
    assert grpc.StatusCode.PERMISSION_DENIED not in _NON_RETRYABLE_CODES
    timeline = simulate(
        [
            Event(0, 'update', message=Message('m')),
            Event(10, 'error', code=grpc.StatusCode.PERMISSION_DENIED),
            Event(30, 'error', code=grpc.StatusCode.PERMISSION_DENIED),
        ]
    )
    assert timeline.stopped_at is None
    capped = simulate(
        [Event(0, 'update', message=Message('m'))]
        + [
            Event(10 + i * 5, 'error', code=grpc.StatusCode.PERMISSION_DENIED)
            for i in range(8)
        ]
    )
    assert capped.attempts[-1].backoff == 5


def test_stream_end_reconnects_and_retry_connect_false_fails_closed() -> None:
    timeline = simulate(
        [Event(0, 'update', message=Message('m')), Event(10, 'drop')],
        horizon=20,
    )
    assert timeline.stopped_at is None
    assert timeline.attempts[-1].backoff == 0.1

    closed = simulate(
        [Event(0, 'update', message=Message('m')), Event(10, 'drop')],
        retry_connect=False,
    )
    assert closed.stopped_at == 10
    assert closed.stop_reason == 'stream ended (fail-closed)'


def test_idle_stream_does_not_refresh_material() -> None:
    timeline = simulate(
        [
            Event(0, 'update', message=Message('m')),
            Event(10, 'silent'),
            Event(20, 'error'),
        ]
    )
    assert [at for at, _ in timeline.updates] == [0]
    assert timeline.attempts[1].outcome == 'stream open (no data)'


def test_virtual_clock_never_moves_backwards() -> None:
    # A second failure arrives while the first backoff (0.1s) is still pending.
    timeline = simulate([Event(10, 'error'), Event(10.05, 'error')], horizon=11)
    times = [a.at for a in timeline.attempts]
    assert times == sorted(times)


def test_invalid_argument_stops_the_watcher() -> None:
    timeline = simulate(
        [
            Event(0, 'update', message=Message('m')),
            Event(10, 'error', code=grpc.StatusCode.INVALID_ARGUMENT),
        ]
    )
    assert timeline.stopped_at == 10
    assert 'non-retryable' in (timeline.stop_reason or '')


def test_update_resets_backoff_state() -> None:
    timeline = simulate(
        [
            Event(0, 'update', message=Message('a')),
            Event(1, 'error'),
            Event(2, 'error'),
            Event(3, 'update', message=Message('b')),
            Event(4, 'error'),
        ]
    )
    backoffs = [a.backoff for a in timeline.attempts if a.backoff is not None]
    assert backoffs == [0.1, 0.2, 0.1]


def test_backoff_schedule_is_exponential_then_capped() -> None:
    assert schedule(RetryPolicy(), 8) == [0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 5, 5]


def _policy() -> GuardedPolicy:
    policy = GuardedPolicy(
        PolicyParams(local_grace=120, federated_grace=60, established_drain=30)
    )
    policy.on_update(
        now=0,
        not_after=3600,
        local_domain='local.test',
        federated_domains=frozenset({'foreign.test'}),
        serial=1,
    )
    return policy


def test_transient_outage_keeps_local_but_stops_federated_after_grace() -> None:
    policy = _policy()
    policy.on_fault(now=10, fault=Fault.TRANSIENT)
    at_60 = policy.evaluate(70)
    assert at_60.local.allowed
    assert not at_60.federated.allowed
    assert at_60.stop_new_dials
    assert 'federation' in (at_60.stop_reason or '')


def test_local_grace_is_independent_of_federated_grace() -> None:
    policy = _policy()
    policy.on_fault(now=10, fault=Fault.TRANSIENT)
    at_125 = policy.evaluate(135)
    assert not at_125.local.allowed
    assert 'local grace' in at_125.local.reason


def test_expired_svid_blocks_immediately_regardless_of_grace() -> None:
    policy = GuardedPolicy()
    policy.on_update(
        now=0,
        not_after=100,
        local_domain='local.test',
        federated_domains=frozenset(),
        serial=1,
    )
    policy.on_fault(now=5, fault=Fault.TRANSIENT)
    decision = policy.evaluate(101)
    assert not decision.local.allowed
    assert decision.stop_reason == 'SVID expired'


def test_removed_federated_domain_is_a_tombstone() -> None:
    policy = _policy()
    policy.on_update(
        now=5,
        not_after=3600,
        local_domain='local.test',
        federated_domains=frozenset({'foreign.test'}),
        serial=2,
    )
    assert policy.federated_domains_for_new_handshake() == frozenset({'foreign.test'})
    # Removing a domain leaves a tombstone.
    policy.on_update(
        now=6,
        not_after=3600,
        local_domain='local.test',
        federated_domains=frozenset({'other.test'}),
        serial=3,
    )
    assert policy.removed == {'foreign.test': 6}
    assert 'foreign.test' not in policy.federated_domains_for_new_handshake()


def test_baseline_keeps_everything_after_permission_denied() -> None:
    baseline = BaselinePolicy()
    baseline.on_update(
        now=0,
        not_after=100,
        local_domain='local.test',
        federated_domains=frozenset({'foreign.test'}),
        serial=1,
    )
    baseline.on_fault(now=10, fault=Fault.TRANSIENT)
    evaluation = baseline.evaluate(10_000)
    assert evaluation.local.allowed
    assert evaluation.federated.allowed


def test_established_connections_drain_after_stop() -> None:
    policy = _policy()
    policy.on_fault(now=10, fault=Fault.TRANSIENT)
    _tick(policy, 0, 72)
    during = policy.evaluate(72)
    _tick(policy, 72, 105)
    after = policy.evaluate(105)
    assert during.stop_new_dials
    assert during.established.allowed
    assert not after.established.allowed


def test_current_spiffetls_trust_update_is_add_only() -> None:
    local = mat.make_authority('local')
    removed = mat.make_authority('removed')
    kept = mat.make_authority('kept')
    client = mat.make_identity('c', 'spiffe://local.test/client', local)
    server = mat.make_identity('s', 'spiffe://removed.test/server', removed, server=True)
    result = probe_removal(
        client_identity=client,
        server_identity=server,
        local_ca=local,
        removed_ca=removed,
        kept_ca=kept,
    )
    assert result['before']['ok']
    assert result['after_same_unused_context']['ok'] is True, (
        'spiffetls applies bundle updates with add_cert only, so the removed root '
        'remains trusted on an existing SSL.Context'
    )
    assert result['after_fresh_context']['ok'] is False
    assert 'already been used' in str(result['used_context_update_error'])


def test_scenarios_are_deterministic_and_cover_four_faults() -> None:
    first = {s.key: s.as_dict() for s in run_all()}
    second = {s.key: s.as_dict() for s in run_all()}
    assert set(first) == {'transient', 'permanent_auth', 'expiry', 'trust_removal'}
    for key in first:
        assert first[key]['attempts'] == second[key]['attempts']
        assert first[key]['checkpoints'] == second[key]['checkpoints']


def test_scenarios_show_expected_divergence() -> None:
    results = {s.key: s for s in run_all()}
    expiry = results['expiry']
    past = expiry.checkpoints[-1]
    assert past.baseline.local.allowed and not past.guarded.local.allowed
    assert any(not check['ok'] for check in past.tls)

    removal = results['trust_removal']
    first = removal.checkpoints[0]
    assert 'rejecting other.test' in first.guarded.federated.reason
    assert any(
        check['label'].startswith('after removal, same SSL.Context') and check['ok']
        for check in first.tls
    )
