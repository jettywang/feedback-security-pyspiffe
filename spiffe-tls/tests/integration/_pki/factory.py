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
from dataclasses import dataclass
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


@dataclass
class CertificateAuthority:
    """A self-signed root CA with its private key."""

    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey

    def sign_leaf(
        self,
        spiffe_id: str,
        *,
        extra_uri_sans: Optional[List[str]] = None,
    ) -> "LeafCertificate":
        private_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svid")])
        uri_sans = [spiffe_id]
        if extra_uri_sans:
            uri_sans.extend(extra_uri_sans)

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOT_BEFORE)
            .not_valid_after(_NOT_AFTER)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(uri) for uri in uri_sans]
                ),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(self.private_key, hashes.SHA256())
        )

        return LeafCertificate(certificate=certificate, private_key=private_key)


@dataclass
class LeafCertificate:
    """An end-entity SVID certificate with its private key."""

    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey

    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def create_certificate_authority(common_name: str) -> CertificateAuthority:
    """Creates a fresh self-signed root CA."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return CertificateAuthority(certificate=certificate, private_key=private_key)
