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

import logging

from typing import TypedDict, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain
from spiffetls.tlsconfig.authorize import authorize_any, authorize_id

from _pki.factory import CertificateAuthority, create_certificate_authority
from _pki.harness import (
    FakeX509Source,
    HandshakeOutcome,
    build_bundle_set,
    build_svid,
    run_mtls_handshake,
)
from pytest import LogCaptureFixture

DOMAIN_A = "alpha.example"
DOMAIN_B = "beta.example"
ID_A = f"spiffe://{DOMAIN_A}/workload-a"
ID_B = f"spiffe://{DOMAIN_B}/workload-b"


class PkiMaterials(TypedDict):
    root_a: CertificateAuthority
    root_b: CertificateAuthority
    source_a: FakeX509Source
    source_b: FakeX509Source
    rogue_source_b: FakeX509Source
    rotated_source_a: FakeX509Source
    rogue_leaf: x509.Certificate


def _build_sources() -> PkiMaterials:
    # Two independent test roots, one per trust domain.
    root_a = create_certificate_authority("root-alpha")
    root_b = create_certificate_authority("root-beta")

    # Legitimate leaves: each root only signs identities of its own domain.
    leaf_a = root_a.sign_leaf(ID_A)
    leaf_b = root_b.sign_leaf(ID_B)

    # Rogue leaf: domain A's CA signs a domain B SPIFFE ID. Root A is still a
    # fully trusted authority in the verifier's pooled store.
    rogue_b_signed_by_a = root_a.sign_leaf(ID_B)

    # Rotated root for domain A, coexisting in the same bundle.
    root_a_rotated = create_certificate_authority("root-alpha-rotated")
    leaf_a_rotated = root_a_rotated.sign_leaf(ID_A)

    source_a = FakeX509Source(
        build_svid(ID_A, leaf_a),
        build_bundle_set(
            {
                DOMAIN_A: {root_a.certificate, root_a_rotated.certificate},
                DOMAIN_B: {root_b.certificate},
            }
        ),
    )
    source_b = FakeX509Source(
        build_svid(ID_B, leaf_b),
        build_bundle_set(
            {
                DOMAIN_A: {root_a.certificate, root_a_rotated.certificate},
                DOMAIN_B: {root_b.certificate},
            }
        ),
    )
    rogue_source_b = FakeX509Source(
        build_svid(ID_B, rogue_b_signed_by_a),
        build_bundle_set(
            {
                DOMAIN_A: {root_a.certificate, root_a_rotated.certificate},
                DOMAIN_B: {root_b.certificate},
            }
        ),
    )
    rotated_source_a = FakeX509Source(
        build_svid(ID_A, leaf_a_rotated),
        build_bundle_set(
            {
                DOMAIN_A: {root_a.certificate, root_a_rotated.certificate},
                DOMAIN_B: {root_b.certificate},
            }
        ),
    )

    return {
        "root_a": root_a,
        "root_b": root_b,
        "source_a": source_a,
        "source_b": source_b,
        "rogue_source_b": rogue_source_b,
        "rotated_source_a": rotated_source_a,
        "rogue_leaf": rogue_b_signed_by_a.certificate,
    }


def _assert_failure(outcome: HandshakeOutcome, leg: str) -> None:
    error = outcome.server_error if leg == "server" else outcome.client_error
    assert error is not None, "expected the TLS handshake to fail"
    message = str(error)
    assert "certificate verify failed" in message or "alert" in message.lower(), message


def test_legitimate_cross_domain_federation_handshake_succeeds() -> None:
    materials = _build_sources()

    outcome = run_mtls_handshake(
        materials["source_a"],
        materials["source_b"],
        server_authorize_fn=authorize_any(),
        client_authorize_fn=authorize_any(),
    )

    assert outcome.server_ok, outcome.server_error
    assert outcome.client_ok, outcome.client_error


def test_rogue_ca_signing_foreign_domain_id_is_rejected(caplog: LogCaptureFixture) -> None:
    materials = _build_sources()

    # Sanity check: the rogue leaf really declares a domain B identity while
    # being signed by the trusted domain A root.
    rogue = materials["rogue_leaf"]
    assert "root-alpha" in rogue.issuer.rfc4514_string()
    san_ext = rogue.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_value = cast(x509.SubjectAlternativeName, san_ext.value)
    uri_sans = san_value.get_values_for_type(x509.UniformResourceIdentifier)
    assert uri_sans == [ID_B]

    with caplog.at_level(logging.ERROR, logger="spiffetls.tlsconfig.verifier"):
        # Rogue client (domain B ID signed by domain A CA) connects to a domain A
        # server. Both sides hold root A as trusted, yet the binding must reject.
        outcome = run_mtls_handshake(
            materials["source_a"],
            materials["rogue_source_b"],
        )

    assert not outcome.server_ok
    _assert_failure(outcome, "server")
    assert outcome.server_error is not None
    assert "certificate verify failed" in str(outcome.server_error)
    assert any(
        "not anchored to the bundle of its trust domain" in record.message
        for record in caplog.records
    )

    # Mirror case: a rogue server presenting the same mis-issued certificate must
    # be rejected by an honest client during the same handshake.
    with caplog.at_level(logging.ERROR, logger="spiffetls.tlsconfig.verifier"):
        mirror = run_mtls_handshake(
            materials["rogue_source_b"],
            materials["source_a"],
        )

    assert not mirror.client_ok
    _assert_failure(mirror, "client")
    assert any(
        "not anchored to the bundle of its trust domain" in record.message
        for record in caplog.records
    )


def test_same_domain_ca_rotation_keeps_handshake_working() -> None:
    materials = _build_sources()

    # The rotated leaf is signed by the second authority in the domain A bundle,
    # proving multiple coexisting roots (rotation overlap) still validate.
    outcome = run_mtls_handshake(
        materials["rotated_source_a"],
        materials["source_b"],
    )

    assert outcome.server_ok, outcome.server_error
    assert outcome.client_ok, outcome.client_error


def test_unknown_trust_domain_is_rejected() -> None:
    root_c = create_certificate_authority("root-gamma")
    leaf_c = root_c.sign_leaf("spiffe://gamma.example/workload-c")

    source_c = FakeX509Source(
        build_svid("spiffe://gamma.example/workload-c", leaf_c),
        # Domain C only trusts itself; the domain A peer has no gamma bundle.
        build_bundle_set({"gamma.example": {root_c.certificate}}),
    )

    outcome = run_mtls_handshake(
        _build_sources()["source_a"],
        source_c,
    )

    assert not outcome.server_ok
    assert not outcome.client_ok
    _assert_failure(outcome, "server")
    _assert_failure(outcome, "client")


def test_application_authorization_runs_after_binding() -> None:
    materials = _build_sources()

    # Binding passes (legitimate federated identity), but the application only
    # allows a different ID: authorization must still be enforced afterward.
    outcome = run_mtls_handshake(
        materials["source_a"],
        materials["source_b"],
        server_authorize_fn=authorize_id(SpiffeId(f"spiffe://{DOMAIN_B}/someone-else")),
        client_authorize_fn=authorize_any(),
    )

    assert not outcome.server_ok
    _assert_failure(outcome, "server")


def test_bundle_lookup_uses_leaf_declared_domain() -> None:
    # Direct unit-level guard that a bundle exists per domain and the rogue
    # leaf's declared domain resolves to a bundle that does not contain root A.
    materials = _build_sources()
    source_a = materials["source_a"]
    assert isinstance(source_a, FakeX509Source)

    bundle_b = source_a.get_bundle_for_trust_domain(TrustDomain(DOMAIN_B))
    assert bundle_b is not None
    assert isinstance(bundle_b, X509Bundle)
    bundle_a = source_a.get_bundle_for_trust_domain(TrustDomain(DOMAIN_A))
    assert bundle_a is not None

    def pem_set(bundle: X509Bundle) -> set[bytes]:
        return {ca.public_bytes(serialization.Encoding.PEM) for ca in bundle.x509_authorities}

    root_a_pem = materials["root_a"].certificate.public_bytes(serialization.Encoding.PEM)
    assert root_a_pem not in pem_set(bundle_b)
    assert root_a_pem in pem_set(bundle_a)
