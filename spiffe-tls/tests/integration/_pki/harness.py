"""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import socket
import threading
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Optional, Protocol, Set, runtime_checkable

from OpenSSL import SSL, crypto
from cryptography.x509 import Certificate

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from spiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain
from spiffe.svid.x509_svid import X509Svid
from spiffetls.context import create_ssl_context

from _pki.factory import LeafCertificate


@runtime_checkable
class X509SourceLike(Protocol):
    """Structural shape of the X509Source surface used by the TLS context."""

    @property
    def svid(self) -> X509Svid: ...

    @property
    def bundles(self) -> FrozenSet[X509Bundle]: ...

    def subscribe_for_updates(self, callback: Callable[[], None]) -> None: ...


class FakeX509Source:
    """Minimal X509Source stand-in backed by locally generated PKI material."""

    def __init__(
        self,
        svid: X509Svid,
        bundle_set: X509BundleSet,
    ) -> None:
        self._svid = svid
        self._bundle_set = bundle_set

    @property
    def svid(self) -> X509Svid:
        return self._svid

    @property
    def bundles(self) -> FrozenSet[X509Bundle]:
        return frozenset(self._bundle_set.bundles)

    def get_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> Optional[X509Bundle]:
        return self._bundle_set.get_bundle_for_trust_domain(trust_domain)

    def subscribe_for_updates(self, callback: Callable[[], None]) -> None:
        pass

    def close(self) -> None:
        pass


def build_svid(spiffe_id: str, leaf: LeafCertificate) -> X509Svid:
    """Builds an X509Svid from a generated leaf without Workload API validation."""
    return X509Svid(
        spiffe_id=SpiffeId(spiffe_id),
        cert_chain=[leaf.certificate],
        private_key=leaf.private_key,
    )


def build_bundle_set(authorities: dict[str, Set[Certificate]]) -> X509BundleSet:
    """Builds a bundle set mapping trust domain names to root CA sets."""
    bundles = {
        TrustDomain(domain): X509Bundle(TrustDomain(domain), set(certs))
        for domain, certs in authorities.items()
    }
    return X509BundleSet(bundles)


@dataclass
class HandshakeOutcome:
    """Result of a real local mTLS handshake."""

    server_ok: bool
    client_ok: bool
    server_error: Optional[Exception]
    client_error: Optional[Exception]


def run_mtls_handshake(
    server_source: X509SourceLike,
    client_source: X509SourceLike,
    *,
    server_authorize_fn: Optional[Callable[[crypto.X509], bool]] = None,
    client_authorize_fn: Optional[Callable[[crypto.X509], bool]] = None,
) -> HandshakeOutcome:
    """Runs a genuine bidirectional TLS 1.3 handshake over a socket pair.

    No network port is bound: the two endpoints talk through a connected
    ``socket.socketpair``. Both sides require and verify a peer certificate, so
    a failure on either leg surfaces the trust-domain binding behavior of the
    real OpenSSL verification path.
    """
    server_ctx = _context(
        SSL.TLS_SERVER_METHOD,
        server_source,
        server_authorize_fn,
    )
    client_ctx = _context(
        SSL.TLS_CLIENT_METHOD,
        client_source,
        client_authorize_fn,
    )

    server_sock, client_sock = socket.socketpair()
    server_conn = SSL.Connection(server_ctx, server_sock)
    server_conn.set_accept_state()
    client_conn = SSL.Connection(client_ctx, client_sock)
    client_conn.set_connect_state()

    errors: List[Optional[Exception]] = [None, None]

    def server_handshake() -> None:
        try:
            server_conn.do_handshake()
        except Exception as e:  # noqa: BLE001 - surfaced as handshake evidence
            errors[0] = e

    def client_handshake() -> None:
        try:
            client_conn.do_handshake()
        except Exception as e:  # noqa: BLE001 - surfaced as handshake evidence
            errors[1] = e

    server_thread = threading.Thread(target=server_handshake)
    client_thread = threading.Thread(target=client_handshake)
    server_thread.start()
    client_thread.start()
    server_thread.join(timeout=10)
    client_thread.join(timeout=10)

    server_ok = errors[0] is None
    client_ok = errors[1] is None

    server_conn.close()
    client_conn.close()
    server_sock.close()
    client_sock.close()

    return HandshakeOutcome(
        server_ok=server_ok,
        client_ok=client_ok,
        server_error=errors[0],
        client_error=errors[1],
    )


def _context(
    method: int,
    source: X509SourceLike,
    authorize_fn: Optional[Callable[[crypto.X509], bool]],
) -> SSL.Context:
    # create_ssl_context is the exact code path used by dial()/listen(); the
    # fake source is structurally compatible at runtime.
    ssl_context: SSL.Context = create_ssl_context(
        method,
        source,  # type: ignore[arg-type]
        authorize_fn,
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        False,
    )
    ssl_context.set_min_proto_version(SSL.TLS1_3_VERSION)
    ssl_context.set_max_proto_version(SSL.TLS1_3_VERSION)
    return ssl_context
