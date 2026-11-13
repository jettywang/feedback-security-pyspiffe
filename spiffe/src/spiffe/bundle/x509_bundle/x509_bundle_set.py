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
This module manages X509BundleSet objects.
"""

from types import MappingProxyType
from typing import TYPE_CHECKING, Iterable, Mapping, Optional, Union

from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['X509BundleSet']

if TYPE_CHECKING:
    from spiffe.bundle.x509_bundle.x509_bundle_set_builder import X509BundleSetBuilder


class X509BundleSet(object):
    """An immutable set of X509Bundles keyed by trust domain.

    An ``X509BundleSet`` is a snapshot. The mapping and contained bundles
    cannot be changed after construction. Use
    :class:`~spiffe.bundle.x509_bundle.x509_bundle_set_builder.X509BundleSetBuilder`
    to construct or update a set.
    """

    __slots__ = ('_bundles',)

    def __init__(
        self, bundles: Optional[Mapping[Union[TrustDomain, str], X509Bundle]] = None
    ) -> None:
        """Creates a new immutable X509BundleSet.

        Args:
            bundles: Bundles keyed by TrustDomain. The mapping is copied.
        """

        by_name = {}
        if bundles:
            for trust_domain, bundle in bundles.items():
                name = _trust_domain_name(trust_domain)
                if name != bundle.trust_domain.name:
                    raise ValueError(
                        'Bundle trust domain does not match the supplied trust domain'
                    )
                by_name[name] = bundle
        object.__setattr__(self, '_bundles', MappingProxyType(by_name))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f'{type(self).__name__} is immutable')

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f'{type(self).__name__} is immutable')

    @property
    def bundles(self) -> frozenset[X509Bundle]:
        """Returns an immutable set of all X509Bundles."""
        return frozenset(self._bundles.values())

    def get_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> Optional[X509Bundle]:
        """Returns the X509Bundle object for the given trust domain.

        Args:
            trust_domain: The TrustDomain to get an X509Bundle.

        Returns:
            An immutable X509Bundle snapshot for the given TrustDomain.
            None if the TrustDomain is not found in the set.
        """
        return self._bundles.get(trust_domain.name)

    @classmethod
    def of(cls, bundle_list: Iterable[X509Bundle]) -> 'X509BundleSet':
        """Creates a new X509BundleSet from the given bundle objects.

        Args:
            bundle_list: X509Bundle objects to store in the new X509BundleSet.
        """
        builder = cls.builder()
        builder.put_bundles(bundle_list)
        return builder.build()

    @classmethod
    def builder(
        cls,
        bundles: Optional[Mapping[Union[TrustDomain, str], X509Bundle]] = None,
    ) -> 'X509BundleSetBuilder':
        """Creates a builder for constructing or updating an X509BundleSet."""
        from spiffe.bundle.x509_bundle.x509_bundle_set_builder import X509BundleSetBuilder

        return X509BundleSetBuilder(bundles)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, X509BundleSet):
            return False
        return self._bundles == o._bundles

    def __hash__(self) -> int:
        return hash(frozenset(self._bundles.items()))


def _trust_domain_name(trust_domain: Union[TrustDomain, str]) -> str:
    return trust_domain if isinstance(trust_domain, str) else trust_domain.name

