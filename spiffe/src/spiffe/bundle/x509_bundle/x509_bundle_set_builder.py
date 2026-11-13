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
This module provides the mutable builder used to create X.509 bundle set snapshots.
"""

from typing import TYPE_CHECKING, Dict, Iterable, Mapping, Optional, Union

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['X509BundleSetBuilder']

if TYPE_CHECKING:
    from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet


class X509BundleSetBuilder(object):
    """Builds immutable :class:`X509BundleSet` snapshots.

    The builder is the explicit update interface. Calling :meth:`build`
    returns a snapshot that is independent of later builder changes.
    """

    def __init__(
        self,
        bundles: Optional[Mapping[Union[TrustDomain, str], X509Bundle]] = None,
    ) -> None:
        """Creates a builder seeded with the given bundles.

        Args:
            bundles: Optional bundles keyed by trust domain. The mapping is copied.
        """

        self._bundles: Dict[str, X509Bundle] = {}
        if bundles:
            for trust_domain, bundle in bundles.items():
                self.put(bundle, trust_domain=trust_domain)

    def put(
        self,
        bundle: X509Bundle,
        trust_domain: Optional[Union[TrustDomain, str]] = None,
    ) -> 'X509BundleSetBuilder':
        """Adds or replaces a bundle for its trust domain."""
        key = (
            _trust_domain_name(trust_domain)
            if trust_domain
            else bundle.trust_domain.name
        )
        if key != bundle.trust_domain.name:
            raise ValueError(
                'Bundle trust domain does not match the supplied trust domain'
            )
        self._bundles[key] = bundle
        return self

    def put_bundles(self, bundles: Iterable[X509Bundle]) -> 'X509BundleSetBuilder':
        """Adds or replaces each bundle in the iterable."""
        for bundle in bundles:
            self.put(bundle)
        return self

    def remove(self, trust_domain: Union[TrustDomain, str]) -> 'X509BundleSetBuilder':
        """Removes the bundle for the given trust domain if present."""
        self._bundles.pop(_trust_domain_name(trust_domain), None)
        return self

    def build(self) -> 'X509BundleSet':
        """Returns a new immutable snapshot of the current bundles."""
        from spiffe.bundle.x509_bundle.x509_bundle_set import X509BundleSet

        return X509BundleSet(self._bundles)


def _trust_domain_name(trust_domain: Union[TrustDomain, str]) -> str:
    return trust_domain if isinstance(trust_domain, str) else trust_domain.name

