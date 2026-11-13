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

Shared in-memory SPIFFE materials and a controllable X509Source for TLS tests.

The checked-in DER/PEM test certificates expired in 2021 and therefore cannot be used
for real handshakes, so these helpers mint a fresh CA and two distinct SVID generations
at runtime. They also provide an X509Source double whose rotation instant is fully
controlled by the test.
"""

from __future__ import annotations

import datetime
from typing import Callable, List, NoReturn, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from spiffe import SpiffeId, TrustDomain, X509Bundle, X509BundleSet, X509Svid
from spiffe.workloadapi.x509_context import X509Context

TRUST_DOMAIN = TrustDomain("domain.test")


def _ec_key() -> EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _ca_certificate(ca_key: EllipticCurvePrivateKey) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPIFFE")])
    return (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _leaf_certificate(
    ca_cert: x509.Certificate,
    ca_key: EllipticCurvePrivateKey,
    leaf_key: EllipticCurvePrivateKey,
    spiffe_id: SpiffeId,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPIRE")])
    return (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(str(spiffe_id))]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


class CertificateMaterials:
    """A fresh root CA plus two SVID generations and the matching trust bundle."""

    def __init__(self) -> None:
        self.ca_key = _ec_key()
        self.ca_cert = _ca_certificate(self.ca_key)
        self.bundle = X509Bundle(TRUST_DOMAIN, {self.ca_cert})
        self.bundle_set = X509BundleSet.of([self.bundle])
        self.svid_a = self._mint_svid("service-a")
        self.svid_b = self._mint_svid("service-b")

    def _mint_svid(self, path: str) -> X509Svid:
        spiffe_id = SpiffeId(f"spiffe://{TRUST_DOMAIN.name}/{path}")
        leaf_key = _ec_key()
        leaf = _leaf_certificate(self.ca_cert, self.ca_key, leaf_key, spiffe_id)
        return X509Svid(spiffe_id, [leaf], leaf_key)

    def context(
        self, svid: X509Svid, bundle_set: Optional[X509BundleSet] = None
    ) -> X509Context:
        return X509Context([svid], bundle_set or self.bundle_set)

    @property
    def snapshots(self) -> List[X509Context]:
        return [self.context(self.svid_a), self.context(self.svid_b)]


class ControllableX509Source:
    """X509Source double with an explicitly controlled rotation point.

    Only ``get_x509_context`` and the subscription API are exercised by spiffetls; the
    deprecated ``svid``/``bundles`` accessors deliberately raise so any regression to the
    old split-read implementation fails loudly.
    """

    def __init__(self, snapshots: List[X509Context], rotate_on_read: bool = False) -> None:
        self._snapshots = list(snapshots)
        self._generation = 0
        self._rotate_on_read = rotate_on_read
        self._subscribers: List[Callable[[], None]] = []
        self.context_read_count = 0
        self.closed = False

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def current_snapshot(self) -> X509Context:
        return self._snapshots[self._generation]

    def get_x509_context(self) -> X509Context:
        if self.closed:
            raise RuntimeError("source is closed")
        self.context_read_count += 1
        snapshot = self._snapshots[self._generation]
        # Adversarial mode: a rotation happens between any two reads of the source.
        # An implementation that fetches the SVID and bundles separately would observe
        # two different generations; a single-snapshot implementation is unaffected.
        if self._rotate_on_read:
            self._generation = (self._generation + 1) % len(self._snapshots)
        return snapshot

    def rotate(self) -> None:
        """Advance one generation and notify subscribers (the controlled rotation)."""
        self._generation = (self._generation + 1) % len(self._snapshots)
        for callback in list(self._subscribers):
            callback()

    def set_snapshots(self, snapshots: List[X509Context]) -> None:
        self._snapshots = list(snapshots)
        self._generation = 0
        for callback in list(self._subscribers):
            callback()

    def subscribe_for_updates(self, callback: Callable[[], None]) -> None:
        self._subscribers.append(callback)

    def unsubscribe_for_updates(self, callback: Callable[[], None]) -> None:
        try:
            self._subscribers.remove(callback)
        except ValueError:
            pass

    @property
    def svid(self) -> NoReturn:
        raise AssertionError(
            "spiffetls must use get_x509_context(); the deprecated .svid accessor was used"
        )

    @property
    def bundles(self) -> NoReturn:
        raise AssertionError(
            "spiffetls must use get_x509_context(); the deprecated .bundles accessor was used"
        )

    def close(self) -> None:
        self.closed = True
