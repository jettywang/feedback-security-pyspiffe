"""Certificate and in-memory TLS helpers for the Workload API failure demo.

No sockets are opened: certificates are built with ``cryptography`` and verified
through ``pyOpenSSL`` memory BIOs, using the same trust-store calls as
``spiffetls.context``.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Iterable, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from OpenSSL import SSL, crypto

UTC = dt.timezone.utc


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key_usage(*, ca: bool) -> x509.KeyUsage:
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


@dataclass(frozen=True)
class Authority:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class Identity:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey
    authority: Authority
    spiffe_id: str

    @property
    def not_after(self) -> dt.datetime:
        return self.cert.not_valid_after_utc

    def chain_der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    def key_der(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def make_authority(cn: str, *, valid_for: dt.timedelta = dt.timedelta(days=30)) -> Authority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + valid_for)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(ca=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return Authority(cert, key)


def make_identity(
    cn: str,
    spiffe_id: str,
    authority: Authority,
    *,
    valid_for: dt.timedelta = dt.timedelta(hours=1),
    server: bool = False,
) -> Identity:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(authority.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + valid_for)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(ca=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if server
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.key.public_key()),
            critical=False,
        )
        .sign(authority.key, hashes.SHA256())
    )
    return Identity(cert, key, authority, spiffe_id)


TrustLike = Union[Authority, x509.Certificate]


def _as_cert(anchor: TrustLike) -> x509.Certificate:
    return anchor.cert if isinstance(anchor, Authority) else anchor


def _openssl_cert(cert: x509.Certificate) -> crypto.X509:
    return crypto.load_certificate(
        crypto.FILETYPE_ASN1, cert.public_bytes(serialization.Encoding.DER)
    )


def _context(
    identity: Identity,
    trusted: Iterable[TrustLike],
    *,
    server: bool,
    trusted_at: dt.datetime | None,
) -> SSL.Context:
    context = SSL.Context(SSL.TLS_SERVER_METHOD if server else SSL.TLS_CLIENT_METHOD)
    context.use_certificate(_openssl_cert(identity.cert))
    context.use_privatekey(
        crypto.load_privatekey(
            crypto.FILETYPE_ASN1,
            identity.key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    )
    store = context.get_cert_store()
    assert store is not None
    for authority in trusted:
        store.add_cert(_openssl_cert(_as_cert(authority)))
    if trusted_at is not None:
        store.set_time(trusted_at)
    context.set_verify(
        SSL.VERIFY_PEER | (SSL.VERIFY_FAIL_IF_NO_PEER_CERT if server else 0),
        lambda _conn, _cert, _errno, _depth, ok: bool(ok),
    )
    return context


def _pump(client: SSL.Connection, server: SSL.Connection, limit: int = 60) -> None:
    for _ in range(limit):
        progressed = False
        for src, dst in ((client, server), (server, client)):
            try:
                data = src.bio_read(65536)
            except SSL.WantReadError:
                continue
            if data:
                dst.bio_write(data)
                progressed = True
        for conn in (client, server):
            try:
                conn.do_handshake()
            except SSL.WantReadError:
                continue
            except SSL.Error as err:
                if 'SYSCALL' not in str(err):
                    raise
        if (
            client.get_peer_certificate() is not None
            and server.get_peer_certificate() is not None
        ):
            return
        if not progressed:
            continue
    raise SSL.Error('handshake did not complete')


def handshake(
    client: Identity,
    server: Identity,
    *,
    client_trust: Iterable[TrustLike],
    server_trust: Iterable[TrustLike],
    trusted_at: dt.datetime | None = None,
) -> tuple[crypto.X509, crypto.X509]:
    """Runs a real mutual-TLS handshake over memory BIOs and returns both peer certs."""
    server_conn = SSL.Connection(
        _context(server, server_trust, server=True, trusted_at=trusted_at), None
    )
    server_conn.set_accept_state()
    client_conn = SSL.Connection(
        _context(client, client_trust, server=False, trusted_at=trusted_at), None
    )
    client_conn.set_connect_state()
    try:
        _pump(client_conn, server_conn)
        client_peer = client_conn.get_peer_certificate()
        server_peer = server_conn.get_peer_certificate()
        if client_peer is None or server_peer is None:
            raise SSL.Error('peer certificate missing')
        return client_peer, server_peer
    finally:
        for conn in (client_conn, server_conn):
            try:
                conn.close()
            except Exception:
                pass


def peer_spiffe_id(peer: crypto.X509) -> str:
    from cryptography.x509.oid import ExtensionOID

    cert = x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, peer))
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert isinstance(san, x509.SubjectAlternativeName)
    return san.get_values_for_type(x509.UniformResourceIdentifier)[0]


def client_context(
    identity: Identity,
    trusted: Iterable[TrustLike],
    *,
    trusted_at: dt.datetime | None = None,
) -> SSL.Context:
    return _context(identity, trusted, server=False, trusted_at=trusted_at)


def server_context(
    identity: Identity,
    trusted: Iterable[TrustLike],
    *,
    trusted_at: dt.datetime | None = None,
) -> SSL.Context:
    return _context(identity, trusted, server=True, trusted_at=trusted_at)


def connect(
    client_ctx: SSL.Context,
    server_ctx: SSL.Context,
) -> tuple[SSL.Connection, SSL.Connection]:
    """Performs a real mTLS handshake over memory BIOs and returns live connections."""
    server_conn = SSL.Connection(server_ctx, None)
    server_conn.set_accept_state()
    client_conn = SSL.Connection(client_ctx, None)
    client_conn.set_connect_state()
    _pump(client_conn, server_conn)
    return client_conn, server_conn


def exchange(
    client: SSL.Connection, server: SSL.Connection, payload: bytes = b'ping'
) -> bytes:
    """Sends application data over an established memory-BIO connection."""
    client.send(payload)
    for _ in range(60):
        moved = False
        for src, dst in ((client, server), (server, client)):
            try:
                data = src.bio_read(65536)
            except SSL.WantReadError:
                continue
            if data:
                dst.bio_write(data)
                moved = True
        try:
            return server.recv(4096)
        except SSL.WantReadError:
            if not moved:
                continue
    raise SSL.Error('application data did not arrive')


def handshake_contexts(
    client_ctx: SSL.Context,
    server_ctx: SSL.Context,
) -> tuple[crypto.X509, crypto.X509]:
    client_conn, server_conn = connect(client_ctx, server_ctx)
    try:
        client_peer = client_conn.get_peer_certificate()
        server_peer = server_conn.get_peer_certificate()
        if client_peer is None or server_peer is None:
            raise SSL.Error('peer certificate missing')
        return client_peer, server_peer
    finally:
        for conn in (client_conn, server_conn):
            try:
                conn.close()
            except Exception:
                pass


def close_connections(*conns: SSL.Connection) -> None:
    for conn in conns:
        try:
            conn.close()
        except Exception:
            pass
