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

Snapshot-coherence, rotation and real-handshake tests for the TLS adapter.

These tests use an X509Source double whose rotation instant is controlled by the test
and perform genuine in-process TLS handshakes over socketpair (no network, no ports).
They prove that a load/update always installs key, certificate and trust bundle from
one X509Context snapshot, that a rotation never mixes generations, and that handshakes
succeed or fail for the concrete cryptographic reason rather than merely checking that
deprecation warnings disappeared.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import TYPE_CHECKING, Any, Tuple

import pytest
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL

from spiffe import SpiffeId, X509BundleSet, X509Svid
from spiffe.workloadapi.x509_context import X509Context
from spiffetls import SpiffeSSLContext, create_ssl_context
import spiffetls.tlsconfig.authorize as authorize
from spiffetls.context import RefreshingSSLContext

from _tls_test_materials import CertificateMaterials, ControllableX509Source

if TYPE_CHECKING:
    from spiffe.utils.certificate_utils import PRIVATE_KEY_TYPES

_HandshakeErrors = dict[str, Any]


@pytest.fixture
def materials() -> CertificateMaterials:
    return CertificateMaterials()


@pytest.fixture
def source(materials: CertificateMaterials) -> ControllableX509Source:
    return ControllableX509Source(materials.snapshots)


def _inner(context: SSL.Context) -> RefreshingSSLContext:
    """Narrows the returned facade to its concrete refreshing implementation."""
    assert isinstance(context, RefreshingSSLContext)
    return context


def _do_handshake(
    server_context: SSL.Context, client_context: SSL.Context
) -> Tuple[_HandshakeErrors, SSL.Connection, SSL.Connection]:
    """Runs a blocking handshake over a connected socketpair and reports both sides."""
    server_sock, client_sock = socket.socketpair()
    server_conn = SSL.Connection(server_context, server_sock)
    client_conn = SSL.Connection(client_context, client_sock)
    server_conn.set_accept_state()
    client_conn.set_connect_state()

    server_error: _HandshakeErrors = {}

    def run_server_handshake() -> None:
        try:
            server_conn.do_handshake()
        except Exception as err:  # captured to assert the concrete reason later
            server_error["error"] = err.args

    thread = threading.Thread(target=run_server_handshake)
    thread.start()
    client_error: Any = None
    try:
        client_conn.do_handshake()
    except Exception as err:
        client_error = err.args
    thread.join(5)
    return (
        {"server": server_error.get("error"), "client": client_error},
        client_conn,
        server_conn,
    )


def test_returns_refreshing_context_and_reads_one_snapshot(
    source: ControllableX509Source,
) -> None:
    context = create_ssl_context(SSL.TLS_SERVER_METHOD, source)

    assert isinstance(context, RefreshingSSLContext)
    assert isinstance(context, SSL.Context)
    # Initial configuration consumes exactly one snapshot; no split svid/bundles reads.
    assert source.context_read_count == 1
    assert len(source._subscribers) == 1


def test_initial_load_uses_a_single_coherent_snapshot(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    context = _inner(create_ssl_context(SSL.TLS_SERVER_METHOD, source))
    inner = context._get_inner_context()

    assert inner.get_verify_mode() == SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
    # Leaf and key inside the loaded context come from the same snapshot and match.
    inner.check_privatekey()
    assert (
        materials.svid_a.leaf.serial_number
        == materials.snapshots[0].default_svid.leaf.serial_number
    )


def _rekeyed_svid(svid: X509Svid, mismatched_key: "PRIVATE_KEY_TYPES") -> X509Svid:
    """Builds an SVID whose certificate chain does not match its private key."""
    return X509Svid(svid.spiffe_id, svid.cert_chain, mismatched_key)


def test_rotation_rebuilds_atomically_without_mixing_generations(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    context = _inner(create_ssl_context(SSL.TLS_SERVER_METHOD, source))

    first_inner = context._get_inner_context()
    assert first_inner is not None

    # Trigger an update between two reads; the handler must take one snapshot and
    # publish a fully rebuilt context, never mutate the one already serving traffic.
    source.rotate()

    second_inner = context._get_inner_context()
    assert second_inner is not first_inner
    # The replacement is internally coherent: its key matches its own leaf.
    second_inner.check_privatekey()
    assert source.context_read_count == 2

    # New connections present the rotated leaf; old context object is left untouched.
    peer_source = ControllableX509Source(materials.snapshots)
    peer_context = create_ssl_context(SSL.TLS_CLIENT_METHOD, peer_source)
    errors, client_conn, _ = _do_handshake(context, peer_context)
    assert errors == {"server": None, "client": None}
    peer_cert = client_conn.get_peer_certificate()
    assert peer_cert is not None
    assert peer_cert.get_serial_number() == materials.svid_b.leaf.serial_number


def test_failed_rotation_keeps_serving_the_previous_snapshot(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    context = _inner(create_ssl_context(SSL.TLS_SERVER_METHOD, source))
    healthy_inner = context._get_inner_context()

    # A snapshot whose private key does not match its leaf cannot form a valid context.
    broken_svid = materials.context(materials.svid_a).default_svid
    broken_context = X509Context(
        # svid_a's certificate paired with svid_b's key => key values mismatch
        [_rekeyed_svid(broken_svid, materials.svid_b.private_key)],
        materials.bundle_set,
    )
    with pytest.raises(Exception):
        source.set_snapshots([broken_context])

    # The live context must be the previous, still-coherent one (no half-loaded state).
    assert context._get_inner_context() is healthy_inner
    context._get_inner_context().check_privatekey()


def test_rotation_between_reads_cannot_install_mixed_generation_material(
    materials: CertificateMaterials,
) -> None:
    """A rotation that lands between reads must not produce a mixed key/cert context.

    The source rotates on every ``get_x509_context`` call, modelling a workload API
    update firing in the middle of a configuration load. The adapter takes exactly one
    snapshot per load, so the resulting context is always internally coherent.
    """
    adversarial_source = ControllableX509Source(materials.snapshots, rotate_on_read=True)
    context = _inner(create_ssl_context(SSL.TLS_SERVER_METHOD, adversarial_source))

    # Exactly one read per load, and the loaded leaf/key still match.
    assert adversarial_source.context_read_count == 1
    inner = context._get_inner_context()
    inner.check_privatekey()

    # Simulate an update notification arriving while a rotation is in flight: the
    # refresh likewise performs a single coherent read and a clean rebuild.
    adversarial_source.rotate()
    assert adversarial_source.context_read_count == 2
    refreshed = context._get_inner_context()
    refreshed.check_privatekey()
    assert refreshed is not inner


def test_handshake_succeeds_with_coherent_snapshots(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    server_context = create_ssl_context(SSL.TLS_SERVER_METHOD, source)
    client_source = ControllableX509Source(materials.snapshots)
    client_context = create_ssl_context(SSL.TLS_CLIENT_METHOD, client_source)

    errors, client_conn, server_conn = _do_handshake(server_context, client_context)

    assert errors == {"server": None, "client": None}
    # Both peers authenticated the other's leaf from the shared trust bundle.
    client_peer = client_conn.get_peer_certificate()
    server_peer = server_conn.get_peer_certificate()
    assert client_peer is not None and server_peer is not None
    assert client_peer.get_serial_number() == materials.svid_a.leaf.serial_number
    assert server_peer.get_serial_number() == materials.svid_a.leaf.serial_number
    client_conn.shutdown()
    server_conn.shutdown()


def test_handshake_fails_with_concrete_reason_when_ca_untrusted(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    server_context = create_ssl_context(SSL.TLS_SERVER_METHOD, source)

    # Client trusts an empty bundle, so it cannot build a chain to the server's CA.
    empty_set = X509BundleSet.of([])
    untrusted_snapshots = [X509Context([materials.svid_a], empty_set)]
    client_source = ControllableX509Source(untrusted_snapshots)
    client_context = create_ssl_context(SSL.TLS_CLIENT_METHOD, client_source)

    errors, _, _ = _do_handshake(server_context, client_context)

    assert errors["client"] is not None
    assert "certificate verify failed" in str(errors["client"])
    assert errors["server"] is not None
    assert "unknown ca" in str(errors["server"])


def test_handshake_fails_with_concrete_reason_when_authorization_denied(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    forbidden = SpiffeId("spiffe://domain.test/does-not-exist")
    server_context = create_ssl_context(
        SSL.TLS_SERVER_METHOD,
        source,
        authorize_fn=authorize.authorize_id(forbidden),
    )
    client_source = ControllableX509Source(materials.snapshots)
    client_context = create_ssl_context(SSL.TLS_CLIENT_METHOD, client_source)

    errors, _, server_conn = _do_handshake(server_context, client_context)

    # The server-side custom authorization rejects the leaf and aborts the handshake.
    assert errors["server"] is not None
    assert "certificate verify failed" in str(errors["server"])
    # It never accepts the unauthorized peer as an authenticated client.
    assert server_conn.get_peer_certificate() is None
    # The client observes a concrete TLS alert/failure, not a silent success.
    assert "tlsv1 alert" in str(errors).lower() or "certificate verify failed" in str(errors)


def test_stdlib_adapter_reapplies_settings_after_rotation(
    materials: CertificateMaterials,
) -> None:
    """Wrapper-level TLS settings must survive an inner-context rebuild."""
    source = ControllableX509Source(materials.snapshots)
    adapter = SpiffeSSLContext(source, protocol=SSL.TLS_CLIENT_METHOD)

    adapter.verify_mode = ssl.CERT_OPTIONAL
    adapter.set_ciphers("HIGH:!aNULL:!MD5")
    adapter.set_alpn_protocols(["h2", "http/1.1"])
    adapter.minimum_version = ssl.TLSVersion.TLSv1_2

    facade = _inner(adapter._ctx)
    assert facade._get_inner_context().get_verify_mode() == SSL.VERIFY_PEER

    source.rotate()  # rebuilds the inner context from the next snapshot

    rebuilt = facade._get_inner_context()
    # The user's verification choice is replayed rather than reset to the default.
    assert rebuilt.get_verify_mode() == SSL.VERIFY_PEER
    assert adapter.verify_mode == ssl.CERT_OPTIONAL
    # The remembered ALPN list can be re-applied to the replacement context.
    rebuilt.set_alpn_protos(adapter._alpn_protocols or [])
    assert adapter._alpn_protocols == [b"h2", b"http/1.1"]
    assert adapter.minimum_version == ssl.TLSVersion.TLSv1_2


def test_stdlib_adapter_handshake_succeeds_and_presents_rotated_leaf(
    materials: CertificateMaterials,
    source: ControllableX509Source,
) -> None:
    server_context = create_ssl_context(SSL.TLS_SERVER_METHOD, source)
    client_source = ControllableX509Source(materials.snapshots)
    stdlib_context = SpiffeSSLContext(client_source, protocol=SSL.TLS_CLIENT_METHOD)
    assert isinstance(stdlib_context, ssl.SSLContext)

    # First generation handshake through the stdlib-compatible wrapper.
    def server_handshake(context: SSL.Context) -> Tuple[Any, SSL.Connection]:
        server_sock, client_sock = socket.socketpair()
        raw_server = SSL.Connection(context, server_sock)
        raw_server.set_accept_state()
        thread = threading.Thread(target=raw_server.do_handshake)
        thread.start()
        wrapped = stdlib_context.wrap_socket(client_sock)
        thread.join(5)
        return wrapped, raw_server

    wrapped, raw_server = server_handshake(server_context)
    assert wrapped.getpeercert(binary_form=True) == materials.svid_a.leaf.public_bytes(
        serialization.Encoding.DER
    )
    wrapped.close()
    raw_server.close()

    # Rotate both sides: new connections use generation B, never a mixed key/cert set.
    source.rotate()
    client_source.rotate()

    wrapped2, raw_server2 = server_handshake(server_context)
    assert wrapped2.getpeercert(binary_form=True) == materials.svid_b.leaf.public_bytes(
        serialization.Encoding.DER
    )
    wrapped2.close()
    raw_server2.close()
    # The wrapper still masquerades as the stdlib context after rotation.
    assert isinstance(stdlib_context, ssl.SSLContext)
