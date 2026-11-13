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
from typing import Callable, Optional

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet
from spiffe.spiffe_id.spiffe_id import SCHEME_PREFIX, SpiffeId, SpiffeIdError
from spiffe.utils.errors import X509CertificateError

_logger: logging.Logger = logging.getLogger(__name__)

# A provider returning the current set of trusted bundles, keyed by trust domain.
# Indirection through a callable keeps verification bound to the live materials of
# an X509Source, including CA rotation and federation updates.
BundleSetProvider = Callable[[], X509BundleSet]
AuthorizeFn = Callable[[crypto.X509], bool]


def spiffe_id_from_cert(cert: crypto.X509) -> SpiffeId:
    """Extracts the single SPIFFE ID from the URI SAN of a pyOpenSSL certificate.

    Args:
        cert: The peer leaf certificate.

    Returns:
        The SPIFFE ID declared in the certificate's URI SAN.

    Raises:
        X509CertificateError: If the certificate has no URI SAN, more than one URI
            SAN, or a URI SAN that is not a well-formed SPIFFE ID.
    """
    cryptography_cert = cert.to_cryptography()

    try:
        ext = cryptography_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound as e:
        raise X509CertificateError(
            'Certificate does not contain a Subject Alternative Name extension'
        ) from e

    san_value = ext.value
    if not isinstance(san_value, x509.SubjectAlternativeName):
        raise X509CertificateError(
            'Certificate does not contain a valid Subject Alternative Name extension'
        )

    uri_sans = san_value.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uri_sans) == 0:
        raise X509CertificateError(
            'Certificate does not contain a URI SAN (expected exactly one SPIFFE ID)'
        )

    if len(uri_sans) != 1:
        raise X509CertificateError(
            'Certificate contains multiple URI SAN entries (expected exactly one SPIFFE ID)'
        )

    uri = uri_sans[0]
    if not uri.startswith(SCHEME_PREFIX):
        raise X509CertificateError('Certificate URI SAN is not a SPIFFE ID')

    try:
        return SpiffeId(uri)
    except SpiffeIdError as e:
        raise X509CertificateError(
            f'Certificate contains a malformed SPIFFE ID in the URI SAN: {uri!r}'
        ) from e


def verify_leaf_against_trust_domain(
    leaf: crypto.X509,
    chain: list[crypto.X509],
    bundle_set: X509BundleSet,
) -> SpiffeId:
    """Verifies a leaf is signed by an authority of its own trust domain.

    The trust domain is taken from the SPIFFE ID the leaf itself declares; the
    presented chain is then validated exclusively against the bundle bound to
    that trust domain. A CA trusted for another domain (for example a federated
    root) can therefore never authenticate an identity outside its own domain,
    even when that root is present in the pooled OpenSSL trust store.

    Args:
        leaf: The peer leaf certificate.
        chain: The certificates presented by the peer, ordered from the leaf
            toward the root. The leaf itself is excluded when building the
            untrusted intermediate list.
        bundle_set: The trusted bundles keyed by trust domain.

    Returns:
        The SPIFFE ID extracted from the leaf.

    Raises:
        X509CertificateError: If the leaf has no valid SPIFFE ID, no bundle
            exists for its trust domain, or its chain is not anchored by an
            authority in that bundle.
    """
    spiffe_id = spiffe_id_from_cert(leaf)
    trust_domain = spiffe_id.trust_domain

    bundle = bundle_set.get_bundle_for_trust_domain(trust_domain)
    if bundle is None:
        raise X509CertificateError(f'No trusted bundle found for trust domain {trust_domain}')

    store = crypto.X509Store()
    for authority in bundle.x509_authorities:
        store.add_cert(crypto.X509.from_cryptography(authority))

    # OpenSSL orders the presented chain leaf-first; everything after the leaf is
    # an untrusted intermediate that must chain up to a bundle authority.
    intermediates = [
        crypto.X509.from_cryptography(presented.to_cryptography()) for presented in chain[1:]
    ]

    store_context = crypto.X509StoreContext(store, leaf, intermediates)
    try:
        store_context.verify_certificate()
    except crypto.X509StoreContextError as e:
        raise X509CertificateError(
            f'Leaf SPIFFE ID {spiffe_id} is not anchored to the bundle of its '
            f'trust domain {trust_domain}: {e}'
        ) from e

    return spiffe_id


def build_verify_callback(
    bundle_set_provider: BundleSetProvider,
    authorize_fn: Optional[AuthorizeFn] = None,
    *,
    allow_non_spiffe: bool = False,
) -> Callable[[SSL.Connection, crypto.X509, int, int, int], bool]:
    """Builds the OpenSSL verify callback enforcing trust-domain binding.

    OpenSSL first performs its own chain validation against the pooled trust
    store, which preserves normal federation and same-domain CA rotation. At the
    leaf, the callback re-validates the presented chain against the single bundle
    bound to the leaf's declared trust domain, and only then applies the optional
    application-level authorization function.

    Args:
        bundle_set_provider: Returns the current trusted bundle set.
        authorize_fn: Optional application authorization evaluated after the
            trust-domain binding check passes.
        allow_non_spiffe: When True, a peer leaf without a SPIFFE ID is accepted
            if OpenSSL chain validation already succeeded (web PKI mode). When
            False, such a leaf is rejected.

    Returns:
        A callback suitable for ``SSL.Context.set_verify``.
    """

    def verify_callback(
        connection: SSL.Connection,
        x509: crypto.X509,
        errno: int,
        depth: int,
        preverify_ok: int,
    ) -> bool:
        if not preverify_ok:
            return False

        if depth != 0:
            return True

        try:
            verify_leaf_against_trust_domain(
                x509,
                connection.get_peer_cert_chain() or [],
                bundle_set_provider(),
            )
        except X509CertificateError as e:
            if allow_non_spiffe and not _declares_spiffe_id(x509):
                _logger.warning(
                    'Accepting non-SPIFFE peer certificate based on web PKI trust: %s', e
                )
                return True
            _logger.error('Trust domain verification failed: %s', e)
            return False

        if authorize_fn is not None:
            return bool(authorize_fn(x509))

        return True

    return verify_callback


def _declares_spiffe_id(cert: crypto.X509) -> bool:
    try:
        spiffe_id_from_cert(cert)
    except X509CertificateError:
        return False
    return True
