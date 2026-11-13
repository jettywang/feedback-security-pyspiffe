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
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, cast, runtime_checkable

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import serialization

from spiffe.workloadapi.x509_context import X509Context
from spiffetls.errors import SslContextError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    # Private key types accepted directly by pyOpenSSL's Context.use_privatekey.
    _LoadablePrivateKey = (
        RSAPrivateKey
        | EllipticCurvePrivateKey
        | Ed25519PrivateKey
        | Ed448PrivateKey
        | DSAPrivateKey
        | crypto.PKey
    )
else:  # the alias only feeds a cast, so a runtime stand-in is sufficient
    _LoadablePrivateKey = Any

_logger: logging.Logger = logging.getLogger(__name__)


@runtime_checkable
class X509ContextSource(Protocol):
    """The subset of the X509Source interface consumed by the TLS adapter.

    Declaring the dependency against a protocol lets test doubles stand in for a real
    X509Source while keeping the contract explicit: callers only need a coherent
    snapshot provider and an update subscription.
    """

    def get_x509_context(self) -> X509Context: ...

    def subscribe_for_updates(self, callback: Callable[[], None]) -> None: ...

    def unsubscribe_for_updates(self, callback: Callable[[], None]) -> None: ...


class RefreshingSSLContext(SSL.Context):
    """An ``SSL.Context`` whose key material is rebuilt atomically on rotation.

    The class subclasses :class:`OpenSSL.SSL.Context` for ``isinstance`` and API
    compatibility, but delegates every call to a lazily replaceable *inner* context.
    On a source update a brand-new inner context is configured from a single coherent
    :class:`X509Context` snapshot and then swapped in. This avoids mutating a context
    that has already produced connections (which modern pyOpenSSL rejects) and ensures
    the leaf certificate, private key, chain and trust bundle always belong to the
    same generation: existing connections keep using the context they were created
    with, while new connections observe only the fully assembled new snapshot.
    """

    def __init__(self, method: int) -> None:
        # Do not call SSL.Context.__init__: this object is only a stable facade and
        # never owns an OpenSSL context of its own.
        self._method = method
        self._inner: Optional[SSL.Context] = None
        self._reconfigure_hooks: list[Callable[[SSL.Context], None]] = []

    @property
    def method(self) -> int:
        return self._method

    def add_reconfigure_hook(self, hook: Callable[[SSL.Context], None]) -> None:
        """Registers a hook applied to every inner context, including replacements.

        Lets wrappers re-apply settings (options, verify mode, ciphers, ...) that would
        otherwise be lost when a rotation builds a fresh inner context.
        """
        self._reconfigure_hooks.append(hook)

    def _swap_inner_context(self, inner: SSL.Context) -> None:
        for hook in self._reconfigure_hooks:
            hook(inner)
        self._inner = inner

    def _get_inner_context(self) -> SSL.Context:
        inner = self._inner
        if inner is None:
            raise RuntimeError("RefreshingSSLContext has not been configured")
        return inner

    def __getattr__(self, name: str) -> object:
        # Only invoked when normal lookup fails, so accessing self._inner during
        # __init__ (before it is set) goes through __getattribute__ without recursion.
        inner = self.__getattribute__("_inner")
        if inner is None:
            raise AttributeError(name)
        return getattr(inner, name)


def create_ssl_context(
    method: int,
    x509_source: X509ContextSource,
    authorize_fn: Optional[Callable[[crypto.X509], bool]] = None,
    verify_mode: int = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
    use_system_trusted_cas: bool = False,
) -> SSL.Context:
    """Configures and returns an SSL context for secure connections.

    This function abstracts the complexity of configuring SSL contexts with
    certificates provided by a X509Source, including setting up custom
    certificate verification if needed.

    Args:
        method: SSL method to use (e.g., SSL.TLS_SERVER_METHOD).
        x509_source: Provides the certificates and private keys.
        authorize_fn: Optional callback for additional cert verification.
        verify_mode: Determines the SSL certificate verification strategy.
        use_system_trusted_cas (bool): If True, the SSL context will include the system's trusted Certificate Authorities
        in addition to any custom certificates. Default is False.
        to any custom certificates. Default is False.

    Returns:
        Configured SSL.Context object.

    Raises:
        SslContextError: If SSL context configuration fails.
    """
    ssl_context = RefreshingSSLContext(method)

    def verify_callback(
        connection: SSL.Connection,
        x509: crypto.X509,
        errno: int,
        depth: int,
        preverify_ok: int,
    ) -> bool:
        if not preverify_ok:
            return False
        if depth == 0 and authorize_fn:
            # Perform custom verification at the leaf certificate
            return authorize_fn(x509)

        return bool(preverify_ok)

    try:
        # Take a single coherent snapshot: the SVID (leaf, chain, private key) and the
        # trusted bundles are always read from the same X509Context, never from separate
        # reads of the source that could straddle a rotation.
        inner = _build_inner_context(
            method,
            x509_source.get_x509_context(),
            verify_mode,
            verify_callback,
            use_system_trusted_cas,
        )
        ssl_context._swap_inner_context(inner)

        update_handler = _SourceUpdateHandler(
            ssl_context,
            x509_source,
            verify_mode,
            verify_callback,
            use_system_trusted_cas,
        )
        x509_source.subscribe_for_updates(update_handler)
    except SSL.Error as err:
        raise SslContextError("Error setting up certificates", err) from err
    except SslContextError:
        raise
    except Exception as err:
        raise SslContextError("Unexpected error during SSL context setup", err) from err

    return ssl_context


def _build_inner_context(
    method: int,
    x509_context: X509Context,
    verify_mode: int,
    verify_callback: Callable[..., bool],
    use_system_trusted_cas: bool,
) -> SSL.Context:
    """Builds a fresh, fully configured inner SSL.Context from one snapshot."""
    inner = SSL.Context(method)
    # Configure everything before publishing the context: a failure leaves the
    # currently serving context untouched and never exposes a half-loaded snapshot.
    _load_certificate_chain(inner, x509_context)
    _load_ca_bundles(inner, x509_context)
    inner.set_verify(verify_mode, verify_callback)

    if use_system_trusted_cas:
        inner.set_default_verify_paths()

    return inner


def _load_certificate_chain(ssl_context: SSL.Context, x509_context: X509Context) -> None:
    """
    Loads the certificate chain and private key from the snapshot's SVID into the SSL context.
    """
    try:
        svid = x509_context.default_svid

        # Pass cryptography objects directly (pyOpenSSL accepts them and avoids the
        # deprecated pyOpenSSL X509/PKey wrappers).
        ssl_context.use_certificate(svid.leaf)
        ssl_context.use_privatekey(cast(_LoadablePrivateKey, svid.private_key))

        # Ensure the private key and certificate match; OpenSSL raises here if a key
        # from a different generation than the leaf certificate was installed.
        ssl_context.check_privatekey()

        # Load the rest of certificate chain
        for chain_cert in svid.cert_chain[1:]:
            ssl_context.add_extra_chain_cert(chain_cert)
    except Exception as e:
        raise Exception(f'Error loading certificates into SSL Context: {e}') from e


def _load_ca_bundles(ssl_context: SSL.Context, x509_context: X509Context) -> None:
    """
    Loads the trusted CA certificate bundles from the snapshot into the SSL context.
    """
    try:
        cert_store = ssl_context.get_cert_store()
        if cert_store is None:
            raise RuntimeError("SSL context certificate store is unavailable")

        # X509Store.add_cert still requires a pyOpenSSL X509 wrapper.
        for bundle in x509_context.x509_bundle_set.bundles:
            for ca_cert in bundle.x509_authorities:
                ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
                ca_cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
                cert_store.add_cert(ca_cert_obj)
    except Exception as e:
        raise Exception(f'Error loading trusted CA certificates into SSL Context: {e}') from e


class _SourceUpdateHandler:
    """Captures the per-context verification settings and performs atomic refreshes."""

    def __init__(
        self,
        ssl_context: RefreshingSSLContext,
        x509_source: X509ContextSource,
        verify_mode: int,
        verify_callback: Callable[..., bool],
        use_system_trusted_cas: bool,
    ) -> None:
        self._ssl_context = ssl_context
        self._x509_source = x509_source
        self._verify_mode = verify_mode
        self._verify_callback = verify_callback
        self._use_system_trusted_cas = use_system_trusted_cas

    def __call__(self) -> None:
        # One snapshot for the whole rebuild; the swap is the only observable change.
        x509_context = self._x509_source.get_x509_context()
        new_inner = _build_inner_context(
            self._ssl_context.method,
            x509_context,
            self._verify_mode,
            self._verify_callback,
            self._use_system_trusted_cas,
        )
        self._ssl_context._swap_inner_context(new_inner)
        _logger.info("Certificates updated in SSL context.")
