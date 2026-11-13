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

"""Regression tests for immutable bundle snapshots and source update isolation."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store

from spiffe import JwtBundle, JwtBundleSet, JwtSvid, X509Bundle, X509BundleSet, X509Svid
from spiffe.bundle.jwt_bundle.jwt_bundle_set_builder import JwtBundleSetBuilder
from spiffe.bundle.x509_bundle.x509_bundle_set_builder import X509BundleSetBuilder
from spiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain
from spiffe.workloadapi.jwt_source import JwtSource
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.x509_context import X509Context
from spiffe.workloadapi.x509_source import X509Source
from testutils.jwt import generate_test_jwt_token

TRUST_DOMAIN = TrustDomain('domain.test')


@dataclass(frozen=True)
class _Chain:
    root: x509.Certificate
    intermediate: x509.Certificate
    leaf: x509.Certificate
    leaf_key: bytes

    def leaf_svid(self) -> X509Svid:
        return X509Svid.parse_raw(
            self.leaf.public_bytes(serialization.Encoding.DER), self.leaf_key
        )


def _key_usage(ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=not ca,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _ski(public_key: object) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(public_key)  # type: ignore[arg-type]


def _aki(issuer: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)


def _make_chain(spiffe_id: str = 'spiffe://domain.test/workload') -> _Chain:
    """Generates a currently-valid root -> intermediate -> leaf chain."""
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Bundle Test Root')])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(True), critical=True)
        .add_extension(_ski(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'Bundle Test Intermediate')]
    )
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(True), critical=True)
        .add_extension(_ski(intermediate_key.public_key()), critical=False)
        .add_extension(_aki(root), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Bundle Test Leaf')])
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(intermediate_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(_ski(leaf_key.public_key()), critical=False)
        .add_extension(_aki(intermediate), critical=False)
    )
    leaf = builder.add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
        critical=False,
    ).sign(intermediate_key, hashes.SHA256())
    leaf_key_bytes = leaf_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return _Chain(root, intermediate, leaf, leaf_key_bytes)


def _verifies(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trusted_roots: list[x509.Certificate],
) -> bool:
    verifier = PolicyBuilder().store(Store(trusted_roots)).build_client_verifier()
    try:
        verifier.verify(leaf, intermediates)
        return True
    except x509.verification.VerificationError:
        return False


class _FakeCancelHandler:
    def cancel(self) -> None:
        pass


class _FakeX509Client:
    """Controllable Workload API client for exercising source replacements."""

    def __init__(self, initial: X509Context) -> None:
        self.initial = initial
        self.on_success: Callable[[X509Context], None] | None = None

    def stream_x509_contexts(
        self,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
    ) -> _FakeCancelHandler:
        self.on_success = on_success
        on_success(self.initial)
        return _FakeCancelHandler()

    def close(self) -> None:
        pass


class _FakeJwtClient:
    def __init__(self, initial: JwtBundleSet) -> None:
        self.initial = initial
        self.on_success: Callable[[JwtBundleSet], None] | None = None

    def stream_jwt_bundles(
        self,
        on_success: Callable[[JwtBundleSet], None],
        on_error: Callable[[Exception], None],
    ) -> _FakeCancelHandler:
        self.on_success = on_success
        on_success(self.initial)
        return _FakeCancelHandler()

    def close(self) -> None:
        pass


def _x509_context(chain: _Chain, *roots: x509.Certificate) -> X509Context:
    return X509Context(
        [chain.leaf_svid()],
        X509BundleSet.of([X509Bundle.builder(TRUST_DOMAIN, roots).build()]),
    )


def test_x509_bundle_is_an_immutable_snapshot() -> None:
    chain = _make_chain()
    first = X509Bundle.builder(TRUST_DOMAIN, [chain.root]).build()

    builder = first.builder(TRUST_DOMAIN, [chain.root])
    second = builder.add_authority(chain.leaf).add_authority(chain.intermediate).build()

    assert first.x509_authorities == frozenset([chain.root])
    assert second.x509_authorities == frozenset(
        [chain.root, chain.intermediate, chain.leaf]
    )
    assert first != second

    # Returned views are immutable, so a caller cannot modify them in place.
    with pytest.raises(AttributeError):
        first.x509_authorities.add(chain.leaf)  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        first.x509_authorities |= frozenset([chain.leaf])  # type: ignore[misc]

    # Private state is also frozen, so the snapshot cannot be rebound.
    with pytest.raises(AttributeError):
        first._x509_authorities = frozenset()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        first.trust_domain._name = 'other.test'  # type: ignore[attr-defined]

    # The builder can be reused to create further independent generations.
    third = builder.remove_authority(chain.intermediate).build()
    assert third.x509_authorities == frozenset([chain.root, chain.leaf])
    assert second.x509_authorities == frozenset(
        [chain.root, chain.intermediate, chain.leaf]
    )


def test_x509_bundle_nested_authorities_are_flat_and_isolated() -> None:
    roots = [_make_chain().root for _ in range(3)]
    nested = [[roots[0], roots[1]], [roots[2], roots[0]]]

    snapshot = (
        X509Bundle.builder(TRUST_DOMAIN)
        .add_authorities(authority for group in nested for authority in group)
        .build()
    )

    # Every nested authority is present exactly once.
    assert len(snapshot.x509_authorities) == 3
    assert {cert.subject for cert in snapshot.x509_authorities} == {
        cert.subject for cert in roots
    }

    # Mutating caller-owned nested lists cannot change the snapshot.
    nested[0].clear()
    nested[1].append(_make_chain().root)
    assert len(snapshot.x509_authorities) == 3


def test_x509_bundle_hash_is_stable_and_order_independent() -> None:
    chain = _make_chain()
    forward = X509Bundle.builder(
        TRUST_DOMAIN, [chain.root, chain.intermediate, chain.leaf]
    ).build()
    reverse = X509Bundle.builder(
        TRUST_DOMAIN, [chain.leaf, chain.intermediate, chain.root]
    ).build()

    assert forward == reverse
    assert hash(forward) == hash(reverse)
    assert len({forward, reverse}) == 1

    # Re-adding an existing authority changes neither equality nor hash.
    rebuilt = (
        forward.builder(TRUST_DOMAIN, forward.x509_authorities)
        .add_authority(chain.intermediate)
        .build()
    )
    assert rebuilt == forward
    assert hash(rebuilt) == hash(forward)


def test_x509_bundle_set_is_an_immutable_snapshot_across_generations() -> None:
    first_chain = _make_chain()
    second_chain = _make_chain()
    other = TrustDomain('other.test')

    old_bundle = X509Bundle.builder(TRUST_DOMAIN, [first_chain.root]).build()
    old_set = X509BundleSet.of([old_bundle])
    old_snapshot = old_set.bundles

    new_set = (
        old_set.builder()
        .put(X509Bundle.builder(TRUST_DOMAIN, [second_chain.root]).build())
        .build()
    )

    # The caller's old generation is untouched by the new generation.
    assert old_set.get_bundle_for_trust_domain(TRUST_DOMAIN) is old_bundle
    old_held = old_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    new_held = new_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert old_held is not None and new_held is not None
    assert old_held.x509_authorities == frozenset([first_chain.root])
    assert new_held.x509_authorities == frozenset([second_chain.root])

    # Mutating a caller-owned snapshot collection cannot alter either set.
    with pytest.raises(AttributeError):
        old_snapshot.clear()  # type: ignore[attr-defined]
    assert old_set.get_bundle_for_trust_domain(TRUST_DOMAIN) is old_bundle
    assert len(old_set.bundles) == 1
    assert len(new_set.bundles) == 1

    # Multiple updates, including a nested authority list, produce independent sets.
    newer_set = (
        X509BundleSetBuilder({TRUST_DOMAIN: new_held})
        .put(X509Bundle.builder(other, [second_chain.leaf]).build())
        .put(
            X509Bundle.builder(
                TRUST_DOMAIN, [first_chain.root, first_chain.intermediate]
            ).build()
        )
        .build()
    )
    newer_held = newer_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert newer_held is not None
    assert newer_held.x509_authorities == frozenset(
        [first_chain.root, first_chain.intermediate]
    )
    assert new_held.x509_authorities == frozenset([second_chain.root])
    assert newer_set.get_bundle_for_trust_domain(other) is not None


def test_x509_trust_result_is_not_affected_by_later_generations() -> None:
    chain = _make_chain()
    other_chain = _make_chain()

    old_bundle = X509Bundle.builder(TRUST_DOMAIN, [chain.root]).build()
    old_set = X509BundleSet.of([old_bundle])
    held = old_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert held is not None

    # A valid chain succeeds against the snapshot held by the caller.
    assert _verifies(chain.leaf, [chain.intermediate], list(held.x509_authorities))

    # The source publishes a new generation trusting an unrelated root.
    new_set = (
        old_set.builder()
        .put(X509Bundle.builder(TRUST_DOMAIN, [other_chain.root]).build())
        .build()
    )
    current = new_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert current is not None

    assert _verifies(chain.leaf, [chain.intermediate], list(held.x509_authorities))
    assert not _verifies(
        chain.leaf, [chain.intermediate], list(current.x509_authorities)
    )

    # Attempting to change the old snapshot through its returned collection
    # does not change the trust decision.
    with pytest.raises(AttributeError):
        held.x509_authorities.clear()  # type: ignore[attr-defined]
    assert _verifies(chain.leaf, [chain.intermediate], list(held.x509_authorities))


def test_x509_source_update_does_not_change_held_snapshot() -> None:
    chain = _make_chain(spiffe_id='spiffe://domain.test/workload')
    other_chain = _make_chain()

    fake_client = _FakeX509Client(_x509_context(chain, chain.root))
    source = X509Source(cast(WorkloadApiClient, fake_client))
    assert fake_client.on_success is not None

    held_context = source.get_x509_context()
    held_bundle = source.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert held_bundle is not None
    held_authorities = held_bundle.x509_authorities
    assert held_authorities == frozenset([chain.root])

    # Publish a new generation while the caller holds the old snapshot.
    fake_client.on_success(_x509_context(chain, other_chain.root))

    assert held_bundle.x509_authorities == held_authorities
    assert held_bundle.x509_authorities == frozenset([chain.root])
    old_context_bundle = held_context.x509_bundle_set.get_bundle_for_trust_domain(
        TRUST_DOMAIN
    )
    assert old_context_bundle is not None
    assert old_context_bundle.x509_authorities == frozenset([chain.root])
    current = source.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert current is not None
    assert current.x509_authorities == frozenset([other_chain.root])
    assert _verifies(chain.leaf, [chain.intermediate], list(held_bundle.x509_authorities))
    assert not _verifies(
        chain.leaf, [chain.intermediate], list(current.x509_authorities)
    )


def test_jwt_bundle_is_an_immutable_snapshot_and_hash_is_order_independent() -> None:
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    old_bundle = JwtBundle.builder(TRUST_DOMAIN, {'a': key_a}).build()
    builder = old_bundle.builder(TRUST_DOMAIN, {'a': key_a})
    new_bundle = builder.add_authority('b', key_b).build()

    assert old_bundle.jwt_authorities == {'a': key_a}
    assert new_bundle.jwt_authorities == {'a': key_a, 'b': key_b}
    assert old_bundle.get_jwt_authority('b') is None

    with pytest.raises(TypeError):
        old_bundle.jwt_authorities['b'] = key_b  # type: ignore[index]
    with pytest.raises(AttributeError):
        old_bundle.jwt_authorities.clear()  # type: ignore[attr-defined]

    forward = JwtBundle.builder(TRUST_DOMAIN, {'a': key_a, 'b': key_b}).build()
    reverse = JwtBundle.builder(TRUST_DOMAIN, {'b': key_b, 'a': key_a}).build()
    assert forward == reverse
    assert hash(forward) == hash(reverse)
    assert len({forward, reverse}) == 1


def test_jwt_bundle_set_is_an_immutable_snapshot_across_generations() -> None:
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    old_bundle = JwtBundle.builder(TRUST_DOMAIN, {'kid': key_a}).build()
    old_set = JwtBundleSet.of([old_bundle])
    old_snapshot = old_set.bundles

    new_set = (
        JwtBundleSetBuilder({TRUST_DOMAIN: old_bundle})
        .put(JwtBundle.builder(TRUST_DOMAIN, {'kid': key_b}).build())
        .build()
    )

    old_held = old_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    new_held = new_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert old_held is old_bundle
    assert old_held is not None and new_held is not None
    assert old_held.get_jwt_authority('kid') is key_a
    assert new_held.get_jwt_authority('kid') is key_b
    assert old_snapshot == frozenset([old_bundle])
    assert old_set.bundles is not old_snapshot

    with pytest.raises(TypeError):
        old_set._bundles['other.test'] = old_bundle  # type: ignore[index]
    with pytest.raises(AttributeError):
        old_snapshot.add(new_held)  # type: ignore[attr-defined]


def test_jwt_validation_uses_held_snapshot_not_new_generation() -> None:
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = generate_test_jwt_token(
        private_key_pem=old_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        spiffe_id='spiffe://domain.test/workload',
    )

    old_bundle = JwtBundle.builder(TRUST_DOMAIN, {'kid1': old_key.public_key()}).build()
    held_set = JwtBundleSet.of([old_bundle])

    # Replacing the source's bundle with a new key must not affect the old one.
    new_bundle = JwtBundle.builder(TRUST_DOMAIN, {'kid1': new_key.public_key()}).build()
    new_set = held_set.builder().put(new_bundle).build()

    held_bundle = held_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert held_bundle is not None
    validated = JwtSvid.parse_and_validate(token, held_bundle, {'joe', 'test', 'other'})
    assert validated.spiffe_id == SpiffeId('spiffe://domain.test/workload')

    current_bundle = new_set.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert current_bundle is not None
    with pytest.raises(Exception):
        JwtSvid.parse_and_validate(token, current_bundle, {'joe', 'test', 'other'})

    # Attempts to alter the held bundle's authority mapping are rejected.
    with pytest.raises(TypeError):
        held_bundle.jwt_authorities['kid1'] = new_key.public_key()  # type: ignore[index]
    assert held_bundle.get_jwt_authority('kid1') == old_key.public_key()


def test_jwt_source_update_does_not_change_held_snapshot() -> None:
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    initial_bundle_set = JwtBundleSet.of(
        [JwtBundle.builder(TRUST_DOMAIN, {'kid1': old_key.public_key()}).build()]
    )
    fake_client = _FakeJwtClient(initial_bundle_set)
    source = JwtSource(cast(WorkloadApiClient, fake_client))

    assert fake_client.on_success is not None
    held_bundle = source.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert held_bundle is not None
    held_authorities = held_bundle.jwt_authorities

    fake_client.on_success(
        JwtBundleSet.of(
            [JwtBundle.builder(TRUST_DOMAIN, {'kid1': new_key.public_key()}).build()]
        )
    )

    assert held_bundle.jwt_authorities == held_authorities
    assert held_bundle.get_jwt_authority('kid1') == old_key.public_key()
    current = source.get_bundle_for_trust_domain(TRUST_DOMAIN)
    assert current is not None
    assert current.get_jwt_authority('kid1') == new_key.public_key()

    token = generate_test_jwt_token(
        private_key_pem=old_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        spiffe_id='spiffe://domain.test/workload',
    )
    validated = JwtSvid.parse_and_validate(token, held_bundle, {'joe', 'test', 'other'})
    assert validated.spiffe_id == SpiffeId('spiffe://domain.test/workload')
    with pytest.raises(Exception):
        JwtSvid.parse_and_validate(token, current, {'joe', 'test', 'other'})
