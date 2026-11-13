"""Security-boundary tests for concatenated DER certificate parsing.

These tests characterize how ``parse_der_certificates`` (the shared backend of
``X509Svid.parse_raw`` and ``X509Bundle.parse_raw``) treats the byte-level
security boundary of a concatenated DER stream.

The implementation decodes each certificate with a BER-tolerant pyasn1 decoder
and re-encodes the abstract value to DER before handing it to ``cryptography``.
That round trip normalizes non-canonical *length* encodings (a tolerance issue)
but cannot repair a certificate whose signed content changed (a security issue).

The samples here are generated in memory and kept deliberately small:
  1. valid concatenation of two canonical DER certificates;
  2. non-canonical (redundant leading-zero) length, and BER indefinite length;
  3. garbage bytes placed between / around the certificates;
  4. truncation of the last certificate (and of the first).

For every sample we compare three things:
  * a strict DER reference splitter built on ``cryptography`` (BER is rejected);
  * the SVID entry point (``X509Svid.parse_raw``);
  * the bundle entry point (``X509Bundle.parse_raw``).
Accepted certificates are then verified independently against the CA public key
using the *original* trust material, so a rejected sample can never be silently
"fixed" by re-encoding.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1_modules.rfc5280 import Certificate as Pyasn1Certificate

from spiffe.bundle.x509_bundle.errors import ParseX509BundleError
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.svid.x509_svid import X509Svid
from spiffe.utils.certificate_utils import parse_der_certificates
from spiffe.utils.errors import ParseCertificateError

TRUST_DOMAIN = TrustDomain("example.org")
_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = _NOT_BEFORE + datetime.timedelta(days=30)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


@pytest.fixture(scope="module")
def material() -> dict:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("intermediate-ca"))
        .issuer_name(_name("intermediate-ca"))
        .public_key(ca_key.public_key())
        .serial_number(1000)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("leaf"))
        .issuer_name(_name("intermediate-ca"))
        .public_key(leaf_key.public_key())
        .serial_number(1001)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://example.org/service")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
    key_der = leaf_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {
        "ca_key": ca_key,
        "ca_der": ca_der,
        "leaf_der": leaf_der,
        "key_der": key_der,
    }


def _header_length(der: bytes) -> tuple[int, int]:
    """Returns (header length, declared content length) for a DER SEQUENCE."""
    assert der[0] == 0x30
    first = der[1]
    if first < 0x80:
        return 2, first
    num_bytes = first & 0x1F
    content_length = int.from_bytes(der[2 : 2 + num_bytes], "big")
    return 2 + num_bytes, content_length


def _non_canonical_length(der: bytes) -> bytes:
    """Re-emit the outer SEQUENCE with a redundant leading 0x00 length octet."""
    header_length, content_length = _header_length(der)
    content = der[header_length:]
    length_bytes = content_length.to_bytes((content_length.bit_length() + 7) // 8, "big")
    return (
        bytes([0x30, 0x80 | (len(length_bytes) + 1), 0x00]) + length_bytes + content
    )


def _indefinite_length(der: bytes) -> bytes:
    """Re-emit the outer SEQUENCE using BER indefinite-length encoding."""
    header_length, _ = _header_length(der)
    content = der[header_length:]
    return bytes([0x30, 0x80]) + content + b"\x00\x00"


def _tamper_tbs(der: bytes, *, serial_number: int) -> bytes:
    """Changes a signed field (serial number) while keeping the old signature."""
    asn1_cert, _ = decode(der, Pyasn1Certificate())
    asn1_cert["tbsCertificate"]["serialNumber"] = serial_number
    return encode(asn1_cert)


def _verify(cert: x509.Certificate, public_key) -> None:
    public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )


def _strict_der_split(stream: bytes) -> list[bytes]:
    """Reference splitter: only strict DER (BER/garbage/truncation rejected).

    ``load_der_x509_certificate`` reads one leading certificate and raises
    ``ExtraData`` when bytes remain; on that path we slice off exactly the
    declared DER length and continue, so padding and trailing garbage still
    surface as parse errors rather than being skipped.
    """
    certs = []
    remaining = stream
    while remaining:
        try:
            cert = x509.load_der_x509_certificate(remaining)
        except ValueError as err:
            if "ExtraData" not in str(err):
                raise
            header_length, content_length = _header_length(remaining)
            cert = x509.load_der_x509_certificate(
                remaining[: header_length + content_length]
            )
        canonical = cert.public_bytes(serialization.Encoding.DER)
        certs.append(canonical)
        remaining = remaining[len(canonical) :]
    return certs


# ---------------------------------------------------------------------------
# 1. Valid concatenation
# ---------------------------------------------------------------------------


def test_valid_concat_is_accepted_and_byte_identical(material) -> None:
    stream = material["leaf_der"] + material["ca_der"]

    assert _strict_der_split(stream) == [material["leaf_der"], material["ca_der"]]

    svid = X509Svid.parse_raw(stream, material["key_der"])
    assert len(svid.cert_chain) == 2
    assert svid.leaf.public_bytes(serialization.Encoding.DER) == material["leaf_der"]

    bundle = X509Bundle.parse_raw(TRUST_DOMAIN, stream)
    assert len(bundle.x509_authorities) == 2

    # parse_der_certificates must not mutate already-canonical DER.
    assert [c.public_bytes(serialization.Encoding.DER) for c in parse_der_certificates(stream)] == [
        material["leaf_der"],
        material["ca_der"],
    ]


def test_valid_concat_signature_verifies_independently(material) -> None:
    stream = material["leaf_der"] + material["ca_der"]
    svid = X509Svid.parse_raw(stream, material["key_der"])

    # Verification uses the original CA key, not anything produced by the parser.
    _verify(svid.leaf, material["ca_key"].public_key())


# ---------------------------------------------------------------------------
# 2. Non-canonical / non-DER length encodings (tolerance, not a content change)
# ---------------------------------------------------------------------------


def test_non_canonical_length_rejected_by_strict_der_but_accepted(material) -> None:
    malformed_leaf = _non_canonical_length(material["leaf_der"])
    stream = malformed_leaf + material["ca_der"]

    # cryptography is a strict DER parser and rejects the redundant length.
    with pytest.raises(ValueError):
        x509.load_der_x509_certificate(malformed_leaf)
    with pytest.raises(ValueError):
        _strict_der_split(stream)

    # Both py-spiffe entry points tolerate it via decode -> re-encode.
    svid = X509Svid.parse_raw(stream, material["key_der"])
    assert len(svid.cert_chain) == 2
    # The certificate that ends up validated is the canonical original bytes.
    assert svid.leaf.public_bytes(serialization.Encoding.DER) == material["leaf_der"]

    bundle = X509Bundle.parse_raw(TRUST_DOMAIN, stream)
    assert len(bundle.x509_authorities) == 2

    # Re-encoding only normalized the length octets; the signed content verifies.
    _verify(svid.leaf, material["ca_key"].public_key())


def test_indefinite_length_is_rejected(material) -> None:
    ber_leaf = _indefinite_length(material["leaf_der"])
    stream = ber_leaf + material["ca_der"]

    # BER indefinite length is accepted by the BER codec but not by pyasn1's
    # DER decoder, nor by strict DER parsers.
    decoded, _ = ber_decoder.decode(ber_leaf, Pyasn1Certificate())
    assert encode(decoded) == material["leaf_der"]
    with pytest.raises(ValueError):
        x509.load_der_x509_certificate(ber_leaf)

    with pytest.raises(ParseCertificateError):
        X509Svid.parse_raw(stream, material["key_der"])
    with pytest.raises(ParseX509BundleError):
        X509Bundle.parse_raw(TRUST_DOMAIN, stream)


def test_tampered_content_cannot_be_fixed_by_re_encoding(material) -> None:
    # A non-canonically encoded leaf whose serial number was altered: the
    # structure parses, but the signature no longer matches the TBS content.
    tampered = _non_canonical_length(
        _tamper_tbs(material["leaf_der"], serial_number=999999)
    )
    stream = tampered + material["ca_der"]

    svid = X509Svid.parse_raw(stream, material["key_der"])
    assert svid.leaf.serial_number == 999999
    with pytest.raises(Exception):
        _verify(svid.leaf, material["ca_key"].public_key())

    bundle = X509Bundle.parse_raw(TRUST_DOMAIN, stream)
    assert len(bundle.x509_authorities) == 2


# ---------------------------------------------------------------------------
# 3. Garbage bytes between / around certificates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stream_factory",
    [
        lambda m: m["leaf_der"] + b"\xff" + m["ca_der"],
        lambda m: m["leaf_der"] + b"\x00" + m["ca_der"],
        lambda m: b"\x00" + m["leaf_der"] + m["ca_der"],
        lambda m: m["leaf_der"] + m["ca_der"] + b"\xff",
    ],
)
def test_garbage_is_rejected_by_both_entry_points(material, stream_factory) -> None:
    stream = stream_factory(material)

    with pytest.raises(ValueError):
        _strict_der_split(stream)
    with pytest.raises(ParseCertificateError):
        X509Svid.parse_raw(stream, material["key_der"])
    with pytest.raises(ParseX509BundleError):
        X509Bundle.parse_raw(TRUST_DOMAIN, stream)


# ---------------------------------------------------------------------------
# 4. Truncation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stream_factory",
    [
        lambda m: m["leaf_der"] + m["ca_der"][:-1],
        lambda m: m["leaf_der"] + m["ca_der"][:-50],
        lambda m: m["leaf_der"][:-1] + m["ca_der"],
    ],
)
def test_truncation_is_rejected_by_both_entry_points(material, stream_factory) -> None:
    stream = stream_factory(material)

    with pytest.raises(ValueError):
        _strict_der_split(stream)
    with pytest.raises(ParseCertificateError):
        X509Svid.parse_raw(stream, material["key_der"])
    with pytest.raises(ParseX509BundleError):
        X509Bundle.parse_raw(TRUST_DOMAIN, stream)


def test_dropping_the_last_cert_entirely_changes_chain_length(material) -> None:
    # A clean boundary (full leaf only) is valid but yields a shorter chain.
    stream = material["leaf_der"]
    assert len(_strict_der_split(stream)) == 1

    svid = X509Svid.parse_raw(stream, material["key_der"])
    assert len(svid.cert_chain) == 1
    bundle = X509Bundle.parse_raw(TRUST_DOMAIN, stream)
    assert len(bundle.x509_authorities) == 1
