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

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from spiffe.spiffe_id.spiffe_id import SpiffeId, TrustDomain
from spiffe.utils.errors import X509CertificateError
from spiffetls.tlsconfig.verifier import (
    build_verify_callback,
    spiffe_id_from_cert,
    verify_leaf_against_trust_domain,
)

INTEGRATION_DIR = Path(__file__).parent.parent / "integration"
sys.path.append(str(INTEGRATION_DIR))

from cryptography import x509

from _pki.factory import CertificateAuthority, create_certificate_authority  # noqa: E402

DOMAIN_A = "alpha.example"
DOMAIN_B = "beta.example"
ID_A = f"spiffe://{DOMAIN_A}/workload-a"
ID_B = f"spiffe://{DOMAIN_B}/workload-b"


def _to_openssl(cert: x509.Certificate) -> crypto.X509:
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return crypto.load_certificate(crypto.FILETYPE_PEM, pem)


def _bundle_set(root_a: CertificateAuthority, root_b: CertificateAuthority) -> X509BundleSet:
    return X509BundleSet(
        {
            TrustDomain(DOMAIN_A): X509Bundle(
                TrustDomain(DOMAIN_A),
                {root_a.certificate},
            ),
            TrustDomain(DOMAIN_B): X509Bundle(
                TrustDomain(DOMAIN_B),
                {root_b.certificate},
            ),
        }
    )


def test_spiffe_id_from_cert_extracts_single_uri() -> None:
    root = create_certificate_authority("root")
    leaf = root.sign_leaf(ID_A)

    spiffe_id = spiffe_id_from_cert(_to_openssl(leaf.certificate))

    assert spiffe_id == SpiffeId(ID_A)
    assert spiffe_id.trust_domain == TrustDomain(DOMAIN_A)


def test_spiffe_id_from_cert_rejects_non_spiffe_uri() -> None:
    root = create_certificate_authority("root")
    leaf = root.sign_leaf("https://alpha.example/not-spiffe")

    with pytest.raises(X509CertificateError):
        spiffe_id_from_cert(_to_openssl(leaf.certificate))


def test_own_domain_chain_verifies() -> None:
    root_a = create_certificate_authority("root-a")
    root_b = create_certificate_authority("root-b")
    leaf_a = root_a.sign_leaf(ID_A)
    bundle_set = _bundle_set(root_a, root_b)

    spiffe_id = verify_leaf_against_trust_domain(
        _to_openssl(leaf_a.certificate),
        [_to_openssl(leaf_a.certificate)],
        bundle_set,
    )

    assert spiffe_id == SpiffeId(ID_A)


def test_foreign_ca_cannot_anchor_another_domain_id() -> None:
    root_a = create_certificate_authority("root-a")
    root_b = create_certificate_authority("root-b")
    rogue = root_a.sign_leaf(ID_B)
    bundle_set = _bundle_set(root_a, root_b)

    with pytest.raises(X509CertificateError) as exc_info:
        verify_leaf_against_trust_domain(
            _to_openssl(rogue.certificate),
            [_to_openssl(rogue.certificate)],
            bundle_set,
        )

    assert "not anchored to the bundle of its trust domain" in str(exc_info.value)


def test_unknown_trust_domain_rejected() -> None:
    root_a = create_certificate_authority("root-a")
    root_c = create_certificate_authority("root-c")
    leaf_c = root_c.sign_leaf("spiffe://gamma.example/workload-c")

    bundle_set = X509BundleSet(
        {TrustDomain(DOMAIN_A): X509Bundle(TrustDomain(DOMAIN_A), {root_a.certificate})}
    )

    with pytest.raises(X509CertificateError, match="No trusted bundle found"):
        verify_leaf_against_trust_domain(
            _to_openssl(leaf_c.certificate),
            [_to_openssl(leaf_c.certificate)],
            bundle_set,
        )


def test_verify_callback_rejects_rogue_leaf_even_when_openssl_trusts_root() -> None:
    root_a = create_certificate_authority("root-a")
    root_b = create_certificate_authority("root-b")
    rogue = root_a.sign_leaf(ID_B)
    bundle_set = _bundle_set(root_a, root_b)

    connection = MagicMock()
    connection.get_peer_cert_chain.return_value = [_to_openssl(rogue.certificate)]
    callback = build_verify_callback(lambda: bundle_set)

    # preverify_ok=1 simulates OpenSSL accepting because root A is in the pool.
    assert callback(connection, _to_openssl(rogue.certificate), 0, 0, 1) is False


def test_verify_callback_accepts_legitimate_leaf_and_then_authorizes() -> None:
    root_a = create_certificate_authority("root-a")
    root_b = create_certificate_authority("root-b")
    leaf_b = root_b.sign_leaf(ID_B)
    bundle_set = _bundle_set(root_a, root_b)

    connection = MagicMock()
    connection.get_peer_cert_chain.return_value = [_to_openssl(leaf_b.certificate)]

    allow = MagicMock(return_value=True)
    deny = MagicMock(return_value=False)

    allowed_callback = build_verify_callback(lambda: bundle_set, allow)
    denied_callback = build_verify_callback(lambda: bundle_set, deny)
    leaf = _to_openssl(leaf_b.certificate)

    assert allowed_callback(connection, leaf, 0, 0, 1) is True
    allow.assert_called_once_with(leaf)
    assert denied_callback(connection, leaf, 0, 0, 1) is False


def test_verify_callback_fails_closed_on_failed_preverify() -> None:
    root_a = create_certificate_authority("root-a")
    leaf_a = root_a.sign_leaf(ID_A)
    bundle_set = _bundle_set(root_a, create_certificate_authority("root-b"))

    connection = MagicMock()
    callback = build_verify_callback(lambda: bundle_set)

    assert callback(connection, _to_openssl(leaf_a.certificate), 0, 0, 0) is False
