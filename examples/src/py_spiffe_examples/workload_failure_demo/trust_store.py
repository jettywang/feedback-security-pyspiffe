"""Exercises the real spiffetls trust-store update path.

``spiffetls.create_ssl_context`` subscribes to an ``X509Source`` and, on each
update, calls ``_load_ca_bundles``. That helper only calls
``cert_store.add_cert``; it never removes a certificate. This module proves the
consequence with real handshakes rather than by reading the code.
"""

from __future__ import annotations

import threading
from typing import Callable, FrozenSet, Iterable

from OpenSSL import SSL

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.svid.x509_svid import X509Svid
from spiffetls import create_ssl_context

from . import materials as mat


class FakeSource:
    """Minimal X509Source surface used by spiffetls.context."""

    def __init__(self, svid: X509Svid, bundles: Iterable[X509Bundle]) -> None:
        self._svid = svid
        self._bundles = frozenset(bundles)
        self._subscribers: list[Callable[[], None]] = []
        self._lock = threading.Lock()

    @property
    def svid(self) -> X509Svid:
        return self._svid

    @property
    def bundles(self) -> FrozenSet[X509Bundle]:
        return self._bundles

    def subscribe_for_updates(self, callback: Callable[[], None]) -> None:
        self._subscribers.append(callback)

    def replace_bundles(self, bundles: Iterable[X509Bundle]) -> None:
        with self._lock:
            self._bundles = frozenset(bundles)
        for callback in list(self._subscribers):
            callback()


def _svid(identity: mat.Identity) -> X509Svid:
    return X509Svid.parse_raw(identity.chain_der(), identity.key_der())


def _bundle(domain: str, authority: mat.Authority) -> X509Bundle:
    return X509Bundle.parse_raw(TrustDomain(domain), authority.der())


def probe_removal(
    *,
    client_identity: mat.Identity,
    server_identity: mat.Identity,
    local_ca: mat.Authority,
    removed_ca: mat.Authority,
    kept_ca: mat.Authority,
    kept_peer: mat.Identity | None = None,
) -> dict[str, object]:
    """Returns handshake outcomes for the real spiffetls update paths."""
    server_ctx = mat.server_context(server_identity, [local_ca])
    initial = [_bundle('local.test', local_ca), _bundle('other.test', removed_ca)]
    rotated = [_bundle('local.test', local_ca), _bundle('foreign.test', kept_ca)]

    def attempt(context: SSL.Context, label: str) -> dict[str, object]:
        try:
            mat.handshake_contexts(context, server_ctx)
            return {'label': label, 'ok': True, 'detail': ''}
        except Exception as err:  # noqa: BLE001 - report OpenSSL's real reason
            return {'label': label, 'ok': False, 'detail': str(err)}

    # 1. Pre-removal trust, on its own source/context.
    pre_source = FakeSource(_svid(client_identity), initial)
    pre = create_ssl_context(SSL.TLS_CLIENT_METHOD, pre_source, None, SSL.VERIFY_PEER)
    before = attempt(pre, 'before removal: peer signed by other.test')

    # 2. Same SSL.Context kept deliberately unused (pyOpenSSL freezes a context
    #    once a Connection is built), then hit with an update that removes
    #    other.test. spiffetls applies it with add_cert only.
    unused_source = FakeSource(_svid(client_identity), initial)
    unused = create_ssl_context(SSL.TLS_CLIENT_METHOD, unused_source, None, SSL.VERIFY_PEER)
    unused_source.replace_bundles(rotated)
    after_same = attempt(unused, 'after removal, same SSL.Context (spiffetls add-only update)')

    # 3. Fresh context built from the updated source.
    fresh_source = FakeSource(_svid(client_identity), rotated)
    fresh = create_ssl_context(SSL.TLS_CLIENT_METHOD, fresh_source, None, SSL.VERIFY_PEER)
    after_fresh = attempt(fresh, 'after removal, newly built SSL.Context')

    # 3b. The still-federated domain must keep working after recovery.
    kept_result: dict[str, object] | None = None
    if kept_peer is not None:
        try:
            mat.handshake_contexts(fresh, mat.server_context(kept_peer, [local_ca]))
            kept_result = {
                'label': 'after removal, peer from still-federated foreign.test',
                'ok': True,
                'detail': '',
            }
        except Exception as err:  # noqa: BLE001
            kept_result = {
                'label': 'after removal, peer from still-federated foreign.test',
                'ok': False,
                'detail': str(err),
            }

    # 4. A context that has already carried a connection cannot be mutated at
    #    all. X509Source._notify_subscribers logs the exception and continues.
    used_source = FakeSource(_svid(client_identity), initial)
    used = create_ssl_context(SSL.TLS_CLIENT_METHOD, used_source, None, SSL.VERIFY_PEER)
    attempt(used, 'prime the live context with one handshake')
    update_error: str | None = None
    try:
        used_source.replace_bundles(rotated)
    except Exception as err:  # noqa: BLE001
        update_error = str(err)
    after_used = attempt(used, 'after removal, SSL.Context already used once')

    result: dict[str, object] = {
        'before': before,
        'after_same_unused_context': after_same,
        'after_fresh_context': after_fresh,
        'after_used_context': after_used,
        'used_context_update_error': update_error,
    }
    if kept_result is not None:
        result['after_fresh_kept_peer'] = kept_result
    return result
