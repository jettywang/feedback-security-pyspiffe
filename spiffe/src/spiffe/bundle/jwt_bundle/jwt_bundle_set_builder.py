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
This module provides the mutable builder used to create JWT bundle set snapshots.
"""

from typing import TYPE_CHECKING, Dict, Iterable, Mapping, Optional, Union

from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['JwtBundleSetBuilder']

if TYPE_CHECKING:
    from spiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet


class JwtBundleSetBuilder(object):
    """Builds immutable :class:`JwtBundleSet` snapshots."""

    def __init__(
        self,
        bundles: Optional[Mapping[Union[TrustDomain, str], JwtBundle]] = None,
    ) -> None:
        """Creates a builder seeded with the given bundles.

        Args:
            bundles: Optional bundles keyed by trust domain. The mapping is copied.
        """

        self._bundles: Dict[str, JwtBundle] = {}
        if bundles:
            for trust_domain, bundle in bundles.items():
                self.put(bundle, trust_domain=trust_domain)

    def put(
        self,
        bundle: JwtBundle,
        trust_domain: Optional[Union[TrustDomain, str]] = None,
    ) -> 'JwtBundleSetBuilder':
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

    def put_bundles(self, bundles: Iterable[JwtBundle]) -> 'JwtBundleSetBuilder':
        """Adds or replaces each bundle in the iterable."""
        for bundle in bundles:
            self.put(bundle)
        return self

    def remove(self, trust_domain: Union[TrustDomain, str]) -> 'JwtBundleSetBuilder':
        """Removes the bundle for the given trust domain if present."""
        self._bundles.pop(_trust_domain_name(trust_domain), None)
        return self

    def build(self) -> 'JwtBundleSet':
        """Returns a new immutable snapshot of the current bundles."""
        from spiffe.bundle.jwt_bundle.jwt_bundle_set import JwtBundleSet

        return JwtBundleSet(self._bundles)


def _trust_domain_name(trust_domain: Union[TrustDomain, str]) -> str:
    return trust_domain if isinstance(trust_domain, str) else trust_domain.name

