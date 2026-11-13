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

import datetime
import threading
from typing import Callable, List, Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from spiffe import X509Bundle, X509BundleSet, X509Svid
from spiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.x509_context import X509Context
from spiffe.workloadapi.x509_source import X509Source

TRUST_DOMAIN = TrustDomain('example.org')
FEDERATED_TRUST_DOMAIN = TrustDomain('domain.test')


def _self_signed_cert(
    key: ec.EllipticCurvePrivateKey,
    spiffe_id: Optional[str],
    *,
    ca: bool,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'test')])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if spiffe_id is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def _make_svid(spiffe_id: str, hint: str = '') -> X509Svid:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _self_signed_cert(key, spiffe_id, ca=False)
    return X509Svid(SpiffeId(spiffe_id), [cert], key, hint=hint)


def _make_ca_cert() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    return _self_signed_cert(key, None, ca=True)


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _context(svids: List[X509Svid], bundles: List[X509Bundle]) -> X509Context:
    return X509Context(svids, X509BundleSet.of(bundles))


class _FakeCancelHandler:
    def __init__(self) -> None:
        self.cancelled = threading.Event()

    def cancel(self) -> None:
        self.cancelled.set()


class _ControlledStreamClient:
    """Fake WorkloadApiClient delivering frames pushed synchronously by the test."""

    def __init__(self, initial_context: X509Context) -> None:
        self._initial_context = initial_context
        self.cancel_handler = _FakeCancelHandler()
        self.on_success: Optional[Callable[[X509Context], None]] = None

    def stream_x509_contexts(
        self,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
    ) -> _FakeCancelHandler:
        self.on_success = on_success
        on_success(self._initial_context)
        return self.cancel_handler

    def emit(self, x509_context: X509Context) -> None:
        assert self.on_success is not None
        self.on_success(x509_context)

    def close(self) -> None:
        pass


def _make_source(
    initial_context: X509Context,
    svid_picker: Optional[Callable[[List[X509Svid]], X509Svid]] = None,
) -> tuple[X509Source, _ControlledStreamClient]:
    client = _ControlledStreamClient(initial_context)
    source = X509Source(
        cast(WorkloadApiClient, client), svid_picker=svid_picker, timeout_in_seconds=1
    )
    return source, client


class _IdentityChangeRecorder:
    def __init__(self) -> None:
        self.contexts: List[X509Context] = []

    def __call__(self, x509_context: X509Context) -> None:
        self.contexts.append(x509_context)


def test_identical_frame_does_not_notify_but_legacy_subscribers_still_fire() -> None:
    svid = _make_svid('spiffe://example.org/service')
    ca = _make_ca_cert()
    source, client = _make_source(_context([svid], [X509Bundle(TRUST_DOMAIN, {ca})]))

    recorder = _IdentityChangeRecorder()
    legacy_calls = 0

    def legacy_callback() -> None:
        nonlocal legacy_calls
        legacy_calls += 1

    source.subscribe_for_identity_changes(recorder)
    source.subscribe_for_updates(legacy_callback)

    # Two frames carrying the same identity material in fresh objects.
    for _ in range(2):
        client.emit(_context([svid], [X509Bundle(TRUST_DOMAIN, {ca})]))

    assert recorder.contexts == []
    assert legacy_calls == 2


def test_bundle_authority_reorder_does_not_notify() -> None:
    svid = _make_svid('spiffe://example.org/service')
    ca1 = _make_ca_cert()
    ca2 = _make_ca_cert()
    bundle_forward = X509Bundle.parse_raw(TRUST_DOMAIN, _der(ca1) + _der(ca2))
    source, client = _make_source(_context([svid], [bundle_forward]))

    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)

    bundle_reversed = X509Bundle.parse_raw(TRUST_DOMAIN, _der(ca2) + _der(ca1))
    client.emit(_context([svid], [bundle_reversed]))

    assert recorder.contexts == []


def test_certificate_rotation_notifies_with_new_snapshot() -> None:
    svid = _make_svid('spiffe://example.org/service')
    ca = _make_ca_cert()
    source, client = _make_source(_context([svid], [X509Bundle(TRUST_DOMAIN, {ca})]))

    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)

    rotated = _make_svid('spiffe://example.org/service')
    client.emit(_context([rotated], [X509Bundle(TRUST_DOMAIN, {ca})]))

    assert len(recorder.contexts) == 1
    snapshot = recorder.contexts[0]
    assert snapshot.default_svid.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert _der(snapshot.default_svid.leaf) == _der(rotated.leaf)


def test_unpicked_svid_change_does_not_notify_but_picked_change_does() -> None:
    svid_a = _make_svid('spiffe://example.org/service-a', hint='a')
    svid_b = _make_svid('spiffe://example.org/service-b', hint='b')
    bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})

    def pick_b(svids: List[X509Svid]) -> X509Svid:
        for svid in svids:
            if svid.hint == 'b':
                return svid
        raise ValueError("no SVID with hint 'b'")

    source, client = _make_source(
        _context([svid_a, svid_b], [bundle]), svid_picker=pick_b
    )

    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)

    # The unpicked SVID rotates: no notification.
    rotated_a = _make_svid('spiffe://example.org/service-a', hint='a')
    client.emit(_context([rotated_a, svid_b], [bundle]))
    assert recorder.contexts == []

    # The SVID list is reordered but the picker still selects the same SVID.
    client.emit(_context([svid_b, rotated_a], [bundle]))
    assert recorder.contexts == []

    # The picked identity changes: notification.
    rotated_b = _make_svid('spiffe://example.org/service-b', hint='b')
    client.emit(_context([rotated_a, rotated_b], [bundle]))
    assert len(recorder.contexts) == 1
    assert _der(recorder.contexts[0].default_svid.leaf) == _der(rotated_b.leaf)


def test_trust_domain_removal_and_addition_notify() -> None:
    svid = _make_svid('spiffe://example.org/service')
    own_bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})
    federated_bundle = X509Bundle(FEDERATED_TRUST_DOMAIN, {_make_ca_cert()})
    source, client = _make_source(_context([svid], [own_bundle, federated_bundle]))

    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)

    # Federated trust domain is removed.
    client.emit(_context([svid], [own_bundle]))
    assert len(recorder.contexts) == 1
    removed_snapshot = recorder.contexts[0]
    assert {
        bundle.trust_domain for bundle in removed_snapshot.x509_bundle_set.bundles
    } == {TRUST_DOMAIN}

    # Federated trust domain comes back.
    client.emit(_context([svid], [own_bundle, federated_bundle]))
    assert len(recorder.contexts) == 2


def test_rotation_and_removal_are_not_coalesced() -> None:
    svid = _make_svid('spiffe://example.org/service')
    own_bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})
    federated_bundle = X509Bundle(FEDERATED_TRUST_DOMAIN, {_make_ca_cert()})
    source, client = _make_source(_context([svid], [own_bundle, federated_bundle]))

    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)

    rotated = _make_svid('spiffe://example.org/service')
    client.emit(_context([rotated], [own_bundle, federated_bundle]))
    client.emit(_context([rotated], [own_bundle]))

    assert len(recorder.contexts) == 2
    rotation_snapshot, removal_snapshot = recorder.contexts
    assert _der(rotation_snapshot.default_svid.leaf) == _der(rotated.leaf)
    assert {
        bundle.trust_domain for bundle in rotation_snapshot.x509_bundle_set.bundles
    } == {TRUST_DOMAIN, FEDERATED_TRUST_DOMAIN}
    assert {
        bundle.trust_domain for bundle in removal_snapshot.x509_bundle_set.bundles
    } == {TRUST_DOMAIN}


def test_snapshot_is_not_replaced_by_later_frames() -> None:
    svid = _make_svid('spiffe://example.org/service')
    bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})
    source, client = _make_source(_context([svid], [bundle]))

    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)

    rotated_once = _make_svid('spiffe://example.org/service')
    rotated_twice = _make_svid('spiffe://example.org/service')
    client.emit(_context([rotated_once], [bundle]))
    client.emit(_context([rotated_twice], [bundle]))

    assert len(recorder.contexts) == 2
    first_snapshot = recorder.contexts[0]
    assert _der(first_snapshot.default_svid.leaf) == _der(rotated_once.leaf)
    # The source has moved on, but the delivered snapshot still carries the
    # exact material of the change it describes.
    assert _der(source.get_x509_context().default_svid.leaf) == _der(rotated_twice.leaf)
    assert _der(first_snapshot.default_svid.leaf) == _der(rotated_once.leaf)


def test_callback_may_read_source_and_unsubscribe_without_deadlock() -> None:
    svid = _make_svid('spiffe://example.org/service')
    bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})
    source, client = _make_source(_context([svid], [bundle]))

    observed: List[str] = []
    done = threading.Event()

    def callback(x509_context: X509Context) -> None:
        # Reading the source and unsubscribing from inside the callback must
        # not deadlock.
        current = source.get_x509_context()
        observed.append(str(current.default_svid.spiffe_id))
        source.unsubscribe_for_identity_changes(callback)
        done.set()

    source.subscribe_for_identity_changes(callback)

    client.emit(_context([_make_svid('spiffe://example.org/service')], [bundle]))
    assert done.wait(timeout=5)

    # Already unsubscribed: further changes are not delivered.
    client.emit(_context([_make_svid('spiffe://example.org/service')], [bundle]))
    assert observed == ['spiffe://example.org/service']


def test_unsubscribe_unknown_identity_callback_does_not_raise() -> None:
    svid = _make_svid('spiffe://example.org/service')
    bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})
    source, _ = _make_source(_context([svid], [bundle]))

    source.unsubscribe_for_identity_changes(_IdentityChangeRecorder())


def test_new_subscriber_is_not_replayed_current_state() -> None:
    svid = _make_svid('spiffe://example.org/service')
    bundle = X509Bundle(TRUST_DOMAIN, {_make_ca_cert()})
    source, client = _make_source(_context([svid], [bundle]))

    rotated = _make_svid('spiffe://example.org/service')
    client.emit(_context([rotated], [bundle]))

    # Subscribing after a change does not replay it.
    recorder = _IdentityChangeRecorder()
    source.subscribe_for_identity_changes(recorder)
    assert recorder.contexts == []

    # The next change is delivered with its own snapshot.
    rotated_again = _make_svid('spiffe://example.org/service')
    client.emit(_context([rotated_again], [bundle]))
    assert len(recorder.contexts) == 1
    assert _der(recorder.contexts[0].default_svid.leaf) == _der(rotated_again.leaf)
