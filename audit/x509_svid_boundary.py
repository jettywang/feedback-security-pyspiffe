#!/usr/bin/env python3
"""Diagnostic: what X509Svid.parse/parse_raw actually guarantee, and what is
deferred to later layers (key match, chain verification, TLS handshake).

Generates local test certificates on the fly. Every leaf carries a valid
SPIFFE URI SAN and spec-compliant key usages / EKU; each non-control
scenario breaks exactly one relation:

  ok            control: valid chain, matching key, trusted root
  key_mismatch  private key does not correspond to the leaf certificate
  broken_link   leaf signed by intermediate A, chain presents intermediate B
  reversed      chain order swapped (intermediate first, leaf second)
  untrusted_ca  well-formed chain under a root that is NOT in the trust bundle
  expired       valid chain, but the leaf is expired (bonus: no relation
                broken, yet still not usable)

Layers probed per scenario:
  L1  X509Svid.parse (PEM) / X509Svid.parse_raw (DER)   <- py-spiffe
  L2  private key <-> leaf public key correspondence     <- caller must check
  L3  chain build+verify against the trust bundle        <- caller / TLS stack
  L4  in-memory TLS handshake (server uses the SVID,     <- TLS handshake
      client trusts only the bundle root)

Run from the repo root:  python3 audit/x509_svid_boundary.py
"""
import ssl
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spiffe" / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509 import verification

from spiffe.svid.x509_svid import X509Svid

SPIFFE_URI = "spiffe://example.org/workload/server"
NOW = datetime.now(timezone.utc)


def make_key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(common_name, key, issuer_name=None, issuer_key=None):
    issuer_name = issuer_name or _name(common_name)
    issuer_key = issuer_key or key
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def make_leaf(issuer_cert, issuer_key, key, not_before=None, not_after=None):
    return (
        x509.CertificateBuilder()
        .subject_name(_name("workload"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(hours=1))
        .not_valid_after(not_after or NOW + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(SPIFFE_URI)]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def key_der(key):
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


# ---------------------------------------------------------------- fixtures
def build_fixtures():
    root_key = make_key()
    root = make_ca("trusted-root", root_key)

    inter_a_key = make_key()
    inter_a = make_ca("intermediate-A", inter_a_key, root.subject, root_key)

    inter_b_key = make_key()
    inter_b = make_ca("intermediate-B", inter_b_key, root.subject, root_key)

    evil_root_key = make_key()
    evil_root = make_ca("untrusted-root", evil_root_key)
    evil_inter_key = make_key()
    evil_inter = make_ca("untrusted-intermediate", evil_inter_key,
                         evil_root.subject, evil_root_key)

    leaf_key = make_key()
    other_key = make_key()

    good_leaf = make_leaf(inter_a, inter_a_key, leaf_key)
    broken_link_leaf = make_leaf(inter_a, inter_a_key, leaf_key)
    untrusted_leaf = make_leaf(evil_inter, evil_inter_key, leaf_key)
    expired_leaf = make_leaf(
        inter_a, inter_a_key, leaf_key,
        not_before=NOW - timedelta(days=10),
        not_after=NOW - timedelta(days=1),
    )

    return {
        "root": root,
        "scenarios": {
            "ok": {
                "chain": [good_leaf, inter_a],
                "key": leaf_key,
                "expect": "valid everywhere",
            },
            "key_mismatch": {
                "chain": [good_leaf, inter_a],
                "key": other_key,  # does not match the leaf's public key
                "expect": "parse OK; key match + TLS fail",
            },
            "broken_link": {
                # leaf signed by intermediate-A, but chain presents B
                "chain": [broken_link_leaf, inter_b],
                "key": leaf_key,
                "expect": "parse OK; chain verify + TLS fail",
            },
            "reversed": {
                "chain": [inter_a, good_leaf],  # leaf not first
                "key": leaf_key,
                "expect": "parse REJECTS (positional role check)",
            },
            "untrusted_ca": {
                "chain": [untrusted_leaf, evil_inter],
                "key": leaf_key,
                "expect": "parse OK; bundle verify + TLS fail",
            },
            "expired": {
                "chain": [expired_leaf, inter_a],
                "key": leaf_key,
                "expect": "parse OK; chain verify + TLS fail",
            },
        },
    }


# ------------------------------------------------------------------- layers
def layer1_parse(chain, key):
    results = {}
    pem_chain = b"".join(pem(c) for c in chain)
    der_chain = b"".join(der(c) for c in chain)
    for name, fn in (
        ("parse(PEM)", lambda: X509Svid.parse(pem_chain, key_pem(key))),
        ("parse_raw(DER)", lambda: X509Svid.parse_raw(der_chain, key_der(key))),
    ):
        try:
            svid = fn()
            results[name] = ("ACCEPT", str(svid.spiffe_id))
        except Exception as exc:
            results[name] = ("REJECT", f"{type(exc).__name__}: {exc}")
    return results


def layer2_key_match(chain, key):
    leaf_pub = chain[0].public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if leaf_pub == key_pub:
        return ("MATCH", "private key corresponds to leaf")
    return ("MISMATCH", "private key does NOT correspond to leaf certificate")


def layer3_chain_verify(chain, root):
    try:
        store = verification.Store([root])
        verifier = verification.PolicyBuilder().store(store).build_client_verifier()
        verifier.verify(chain[0], chain[1:])
        return ("VERIFIED", "chain builds to trusted root and is in validity window")
    except Exception as exc:
        return ("FAILED", f"{type(exc).__name__}: {exc}")


def _pump(server_ctx, client_ctx):
    """Drive an in-memory TLS handshake; returns (ok, detail)."""
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    c = client_ctx.wrap_bio(c_in, c_out, server_side=False)
    s_done = c_done = False
    for _ in range(200):
        for ssl_obj, outgoing, peer_in, side in (
            (c, c_out, s_in, "client"),
            (s, s_out, c_in, "server"),
        ):
            done = c_done if side == "client" else s_done
            if not done:
                try:
                    ssl_obj.do_handshake()
                    if side == "client":
                        c_done = True
                    else:
                        s_done = True
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError as exc:
                    return False, f"{side} handshake: {exc.reason or exc}"
            data = outgoing.read()
            if data:
                peer_in.write(data)
        if s_done and c_done:
            return True, f"handshake ok ({c.version()})"
    return False, "handshake did not converge"


def layer4_tls(chain, key, root, tmpdir, tag):
    cert_file = Path(tmpdir) / f"{tag}-chain.pem"
    key_file = Path(tmpdir) / f"{tag}-key.pem"
    root_file = Path(tmpdir) / "trusted-root.pem"
    cert_file.write_bytes(b"".join(pem(c) for c in chain))
    key_file.write_bytes(key_pem(key))
    root_file.write_bytes(pem(root))

    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server.load_cert_chain(str(cert_file), str(key_file))
    except ssl.SSLError as exc:
        return ("REJECT", f"server ctx load_cert_chain: {exc.reason or exc}")

    client = ssl.create_default_context(cafile=str(root_file))
    client.check_hostname = False

    ok, detail = _pump(server, client)
    return ("ACCEPT" if ok else "REJECT", detail)


# --------------------------------------------------------------------- main
def main():
    fixtures = build_fixtures()
    root = fixtures["root"]
    rows = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        for tag, sc in fixtures["scenarios"].items():
            chain, key = sc["chain"], sc["key"]
            l1 = layer1_parse(chain, key)
            l2 = layer2_key_match(chain, key)
            l3 = layer3_chain_verify(chain, root)
            l4 = layer4_tls(chain, key, root, tmpdir, tag)
            rows[tag] = (l1, l2, l3, l4, sc["expect"])

    for tag, (l1, l2, l3, l4, expect) in rows.items():
        print(f"\n=== scenario: {tag}  ({expect})")
        for name, (verdict, detail) in l1.items():
            print(f"  L1 {name:<14} {verdict:<8} {detail}")
        print(f"  L2 {'key match':<14} {l2[0]:<8} {l2[1]}")
        print(f"  L3 {'chain verify':<14} {l3[0]:<8} {l3[1]}")
        print(f"  L4 {'TLS handshake':<14} {l4[0]:<8} {l4[1]}")

    print("\n=== summary (verdicts only)")
    header = (f"{'scenario':<14} {'L1 parse':<10} {'L1 parse_raw':<14} "
              f"{'L2 key':<10} {'L3 chain':<10} {'L4 TLS':<7}")
    print(header)
    print("-" * len(header))
    for tag, (l1, l2, l3, l4, _) in rows.items():
        print(f"{tag:<14} {l1['parse(PEM)'][0]:<10} {l1['parse_raw(DER)'][0]:<14} "
              f"{l2[0]:<10} {l3[0]:<10} {l4[0]:<7}")


if __name__ == "__main__":
    main()
