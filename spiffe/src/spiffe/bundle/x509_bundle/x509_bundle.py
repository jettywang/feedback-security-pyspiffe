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

"""
This module manages X.509 Bundle objects.
"""

from collections.abc import Iterable as IterableABC
from pathlib import Path
from typing import TYPE_CHECKING, FrozenSet, Iterable, Iterator, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from spiffe.errors import ArgumentError
from spiffe.bundle.x509_bundle.errors import (
    X509BundleError,
    SaveX509BundleError,
    ParseX509BundleError,
    LoadX509BundleError,
)
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.utils.certificate_utils import (
    parse_pem_certificates,
    parse_der_certificates,
    load_certificates_bytes_from_file,
    write_certificates_to_file,
)

__all__ = ['X509Bundle']

if TYPE_CHECKING:
    from spiffe.bundle.x509_bundle.x509_bundle_builder import X509BundleBuilder


class X509Bundle(object):
    """Represents an immutable collection of trusted X.509 authorities for a trust domain.

    An ``X509Bundle`` is a value snapshot. Its authorities cannot be changed
    after construction, so handing a bundle to another component does not give
    that component a way to change the source's trust material. Use
    :class:`~spiffe.bundle.x509_bundle.x509_bundle_builder.X509BundleBuilder`
    to construct or update a bundle.
    """

    __slots__ = ('_trust_domain', '_x509_authorities', '_authorities_hash')

    def __init__(
        self,
        trust_domain: TrustDomain,
        x509_authorities: Optional[Iterable[Certificate]] = None,
    ) -> None:
        """Creates an immutable X509Bundle instance.

        Args:
            trust_domain: A TrustDomain instance.
            x509_authorities: A collection of CA certificates. It is copied.

        Raises:
            X509BundleError: In case the trust_domain is empty.
        """

        if not trust_domain:
            raise X509BundleError("Trust domain cannot be empty")

        object.__setattr__(self, '_trust_domain', trust_domain)
        authorities = (
            frozenset(_flatten_authorities(x509_authorities))
            if x509_authorities
            else frozenset()
        )
        object.__setattr__(self, '_x509_authorities', authorities)
        object.__setattr__(self, '_authorities_hash', _hash_authorities(authorities))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f'{type(self).__name__} is immutable')

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f'{type(self).__name__} is immutable')

    @property
    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle."""
        return self._trust_domain

    @property
    def x509_authorities(self) -> FrozenSet[Certificate]:
        """Returns an immutable view of the X.509 authorities in the bundle."""
        return self._x509_authorities

    @classmethod
    def builder(
        cls,
        trust_domain: TrustDomain,
        x509_authorities: Optional[Iterable[Certificate]] = None,
    ) -> 'X509BundleBuilder':
        """Creates a builder for constructing or updating an X.509 bundle."""
        from spiffe.bundle.x509_bundle.x509_bundle_builder import X509BundleBuilder

        return X509BundleBuilder(trust_domain, x509_authorities)

    def save(
        self,
        bundle_path: Path | str,
        encoding: serialization.Encoding,
    ) -> None:
        """Saves the X.509 bundle to a file in disk.

        Args:
            bundle_path: Path to the file the set of X.509 authorities will be written to.
            encoding: Bundle encoding format, either serialization.Encoding.PEM or serialization.Encoding.DER

        Raises:
            ArgumentError: In case the encoding is not either PEM or DER (from serialization.Encoding)
            SaveX509BundleError: In the case the file path in bundle_path cannot be open to write, or there is an error
                                converting or writing the authorities bytes to the file.
        """

        if encoding not in [encoding.PEM, encoding.DER]:
            raise ArgumentError(
                'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(encoding)
            )
        try:
            write_certificates_to_file(bundle_path, encoding, self._x509_authorities)
        except Exception as err:
            raise SaveX509BundleError(bundle_path) from err

    @classmethod
    def parse(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'X509Bundle':
        """Parses an X.509 bundle from an array of bytes containing trusted authorities as PEM blocks.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of X.509 authorities.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            X509BundleError: In case the trust_domain is empty.
            ParseX509BundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            authorities = parse_pem_certificates(bundle_bytes)
        except Exception as err:
            raise ParseX509BundleError(str(err)) from err

        return X509Bundle(trust_domain, authorities)

    @classmethod
    def parse_raw(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'X509Bundle':
        """Parses an X.509 bundle from an array of bytes containing trusted authorities as DER blocks.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of X.509 authorities.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            X509BundleError: In case the trust_domain is empty.
            ParseX509BundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            authorities = parse_der_certificates(bundle_bytes)
        except Exception as err:
            raise ParseX509BundleError(str(err)) from err

        return X509Bundle(trust_domain, authorities)

    @classmethod
    def load(
        cls,
        trust_domain: TrustDomain,
        bundle_path: Path | str,
        encoding: serialization.Encoding,
    ) -> 'X509Bundle':
        """Loads an X.509 bundle from a file in disk containing DER or PEM encoded trusted authorities.

        Args:
            trust_domain: A trust domain to associate to the bundle.
            bundle_path: Path to the file containing a set of X.509 authorities.
            encoding: Bundle encoding format, either serialization.Encoding.PEM or serialization.Encoding.DER.

        Returns:
            An instance of 'X509Bundle' with the X.509 authorities associated to the given trust domain.

        Raises:
            X509BundleError: In case the trust_domain is empty.
            LoadX509BundleError: In case the set of x509_authorities cannot be parsed from the bundle_bytes.
        """

        try:
            bundle_bytes = load_certificates_bytes_from_file(bundle_path)
        except Exception as err:
            raise LoadX509BundleError(str(err)) from err

        if encoding == serialization.Encoding.PEM:
            return cls.parse(trust_domain, bundle_bytes)

        if encoding == serialization.Encoding.DER:
            return cls.parse_raw(trust_domain, bundle_bytes)

        raise ArgumentError(
            'Encoding not supported: {}. Expected \'PEM\' or \'DER\''.format(encoding)
        )

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, X509Bundle):
            return False
        return (
            self._trust_domain == o._trust_domain
            and self._x509_authorities == o._x509_authorities
        )

    def __hash__(self) -> int:
        return hash((self._trust_domain, self._authorities_hash))


def _hash_authorities(authorities: FrozenSet[Certificate]) -> int:
    """Hashes authorities independently of their iteration or insertion order."""
    encoded = sorted(
        authority.public_bytes(serialization.Encoding.DER) for authority in authorities
    )
    return hash(tuple(encoded))


def _flatten_authorities(authorities: Iterable[object]) -> Iterator[Certificate]:
    """Yields authorities from flat or nested iterables, skipping duplicates later."""
    for authority in authorities:
        if isinstance(authority, Certificate):
            yield authority
        elif isinstance(authority, IterableABC) and not isinstance(
            authority, (bytes, bytearray, str)
        ):
            yield from _flatten_authorities(authority)
        else:
            raise TypeError(
                'X.509 authorities must be certificates or nested iterables of certificates'
            )
