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
This module manages JwtBundleSet objects.
"""

from types import MappingProxyType
from typing import TYPE_CHECKING, Iterable, Mapping, Optional, Union

from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['JwtBundleSet']

if TYPE_CHECKING:
    from spiffe.bundle.jwt_bundle.jwt_bundle_set_builder import JwtBundleSetBuilder


class JwtBundleSet(object):
    """An immutable set of JWT bundles keyed by trust domain.

    A ``JwtBundleSet`` is a snapshot. The mapping and contained bundles cannot
    be changed after construction. Use
    :class:`~spiffe.bundle.jwt_bundle.jwt_bundle_set_builder.JwtBundleSetBuilder`
    to construct or update a set.
    """

    __slots__ = ('_bundles',)

    def __init__(
        self, bundles: Optional[Mapping[Union[TrustDomain, str], JwtBundle]] = None
    ) -> None:
        """Creates a new immutable JwtBundleSet.

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
    def bundles(self) -> frozenset[JwtBundle]:
        """Returns an immutable set of all JwtBundles."""
        return frozenset(self._bundles.values())

    def get_bundle_for_trust_domain(self, trust_domain: TrustDomain) -> Optional[JwtBundle]:
        """Returns the JWT bundle of the given trust domain.

        Args:
            trust_domain: The TrustDomain to get a JwtBundle.

        Returns:
            An immutable JwtBundle snapshot for the given TrustDomain.
            None if the TrustDomain is not found in the set.
        """
        return self._bundles.get(trust_domain.name)

    @classmethod
    def of(cls, bundle_list: Iterable[JwtBundle]) -> 'JwtBundleSet':
        """Creates a new JwtBundleSet from the given bundle objects.

        Args:
            bundle_list: JwtBundle objects to store in the new JwtBundleSet.
        """
        builder = cls.builder()
        builder.put_bundles(bundle_list)
        return builder.build()

    @classmethod
    def builder(
        cls,
        bundles: Optional[Mapping[Union[TrustDomain, str], JwtBundle]] = None,
    ) -> 'JwtBundleSetBuilder':
        """Creates a builder for constructing or updating a JwtBundleSet."""
        from spiffe.bundle.jwt_bundle.jwt_bundle_set_builder import JwtBundleSetBuilder

        return JwtBundleSetBuilder(bundles)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, JwtBundleSet):
            return False
        return self._bundles == o._bundles

    def __hash__(self) -> int:
        return hash(frozenset(self._bundles.items()))


def _trust_domain_name(trust_domain: Union[TrustDomain, str]) -> str:
    return trust_domain if isinstance(trust_domain, str) else trust_domain.name

