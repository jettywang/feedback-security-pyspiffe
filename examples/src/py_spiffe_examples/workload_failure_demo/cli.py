"""Command-line entry point for the failure demo."""

from __future__ import annotations

import argparse
import json

from .scenarios import Scenario, run_all


def _yes_no(value: bool) -> str:
    return 'yes' if value else 'no'


def _print_scenario(scenario: Scenario) -> None:
    print(f'\n{scenario.title}')
    print(f'  {scenario.question}')
    print('  Workload API attempts (virtual seconds):')
    for attempt in scenario.timeline.attempts:
        backoff = f' backoff={attempt.backoff:g}s' if attempt.backoff is not None else ''
        code = f' {attempt.code}' if attempt.code else ''
        print(f'    +{attempt.at:7.2f}s  {attempt.outcome}{code}{backoff}')
    if scenario.timeline.stopped_at is not None:
        stopped = scenario.timeline.stopped_at
        print(f'  watcher stopped at +{stopped:.2f}s: {scenario.timeline.stop_reason}')
    for checkpoint in scenario.checkpoints:
        print(f'\n  [t=+{checkpoint.at:g}s] {checkpoint.label}')
        pairs = (
            ('py-spiffe today', checkpoint.baseline),
            ('guarded policy', checkpoint.guarded),
        )
        for name, evaluation in pairs:
            print(f'    {name}:')
            print(
                f'      local SVID     : {_yes_no(evaluation.local.allowed)}'
                f' - {evaluation.local.reason}'
            )
            print(
                f'      federated trust: {_yes_no(evaluation.federated.allowed)}'
                f' - {evaluation.federated.reason}'
            )
            print(
                f'      old connections: {_yes_no(evaluation.established.allowed)}'
                f' - {evaluation.established.reason}'
            )
            stop = _yes_no(evaluation.stop_new_dials)
            reason = f' ({evaluation.stop_reason})' if evaluation.stop_reason else ''
            print(f'      new dials stop : {stop}{reason}')
        print('    real mTLS checks:')
        for check in checkpoint.tls:
            verdict = 'OK  ' if check['ok'] else 'FAIL'
            detail = f"  [{check['detail']}]" if check['detail'] else ''
            print(f'      {verdict} {check["label"]}{detail}')
    for note in scenario.notes:
        print(f'  note: {note}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Workload API failure timelines: cached local SVID vs federated bundles'
    )
    parser.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    args = parser.parse_args()
    scenarios = run_all()
    if args.json:
        print(json.dumps([s.as_dict() for s in scenarios], indent=2, sort_keys=False))
        return
    print('Workload API outage timeline demo (virtual time, real py-spiffe retry policy,')
    print('real pyOpenSSL handshakes over memory BIOs; no sockets and no SPIRE).')
    for scenario in scenarios:
        _print_scenario(scenario)


if __name__ == '__main__':
    main()
