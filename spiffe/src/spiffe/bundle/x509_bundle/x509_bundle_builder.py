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
This module provides the mutable builder used to create X.509 bundle snapshots.
"""

from typing import Iterable, Optional, Set

from cryptography.x509 import Certificate
from spiffe.bundle.x509_bundle.errors import X509BundleError
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle, _flatten_authorities
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['X509BundleBuilder']


class X509BundleBuilder(object):
    """Builds immutable :class:`X509Bundle` snapshots.

    The builder owns the only mutable authority collection. Calling
    :meth:`build` returns a snapshot that is independent of subsequent builder
    changes, so a new bundle generation cannot alter bundles already handed to
    callers.
    """

    def __init__(
        self,
        trust_domain: TrustDomain,
        x509_authorities: Optional[Iterable[Certificate]] = None,
    ) -> None:
        """Creates a builder for an X.509 bundle.

        Args:
            trust_domain: A TrustDomain instance.
            x509_authorities: Initial CA certificates. The collection is copied.

        Raises:
            X509BundleError: In case the trust_domain is empty.
        """

        if not trust_domain:
            raise X509BundleError("Trust domain cannot be empty")

        self._trust_domain = trust_domain
        self._x509_authorities: Set[Certificate] = (
            set(_flatten_authorities(x509_authorities)) if x509_authorities else set()
        )

    @property
    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle being built."""
        return self._trust_domain

    @property
    def x509_authorities(self) -> Set[Certificate]:
        """Returns a copy of the builder's current authority set."""
        return self._x509_authorities.copy()

    def add_authority(self, x509_authority: Certificate) -> 'X509BundleBuilder':
        """Adds an X.509 authority to the bundle being built."""
        self._x509_authorities.add(x509_authority)
        return self

    def add_authorities(
        self, x509_authorities: Iterable[Certificate]
    ) -> 'X509BundleBuilder':
        """Adds X.509 authorities from a flat or nested iterable."""
        self._x509_authorities.update(_flatten_authorities(x509_authorities))
        return self

    def remove_authority(self, x509_authority: Certificate) -> 'X509BundleBuilder':
        """Removes an X.509 authority if present."""
        self._x509_authorities.discard(x509_authority)
        return self

    def build(self) -> 'X509Bundle':
        """Returns a new immutable snapshot of the current bundle contents."""
        return X509Bundle(self._trust_domain, self._x509_authorities)
