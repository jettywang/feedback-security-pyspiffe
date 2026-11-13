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
This module provides the mutable builder used to create JWT bundle snapshots.
"""

from typing import Mapping, Optional

from spiffe.bundle.jwt_bundle.errors import JwtBundleError
from spiffe.bundle.jwt_bundle.jwt_bundle import JWT_PUBLIC_KEY_TYPES, JwtBundle
from spiffe.spiffe_id.spiffe_id import TrustDomain

__all__ = ['JwtBundleBuilder']


class JwtBundleBuilder(object):
    """Builds immutable :class:`JwtBundle` snapshots.

    The builder owns the only mutable authority mapping. Calling :meth:`build`
    returns a snapshot that is independent of subsequent builder changes.
    """

    def __init__(
        self,
        trust_domain: TrustDomain,
        jwt_authorities: Optional[Mapping[str, JWT_PUBLIC_KEY_TYPES]] = None,
    ) -> None:
        """Creates a builder for a JWT bundle.

        Args:
            trust_domain: The TrustDomain to associate with the bundle.
            jwt_authorities: Initial key_id -> public key mapping. It is copied.

        Raises:
            JwtBundleError: In case the trust_domain is empty.
        """

        if not trust_domain:
            raise JwtBundleError("Trust domain cannot be empty")

        self._trust_domain = trust_domain
        self._jwt_authorities = dict(jwt_authorities) if jwt_authorities else {}

    @property
    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle being built."""
        return self._trust_domain

    @property
    def jwt_authorities(self) -> Mapping[str, JWT_PUBLIC_KEY_TYPES]:
        """Returns a copy of the builder's current authorities."""
        return self._jwt_authorities.copy()

    def add_authority(
        self, key_id: str, public_key: JWT_PUBLIC_KEY_TYPES
    ) -> 'JwtBundleBuilder':
        """Adds or replaces the authority for the given key ID."""
        if not key_id:
            raise JwtBundleError('key_id cannot be empty')
        self._jwt_authorities[key_id] = public_key
        return self

    def remove_authority(self, key_id: str) -> 'JwtBundleBuilder':
        """Removes the authority for the given key ID if present."""
        self._jwt_authorities.pop(key_id, None)
        return self

    def build(self) -> 'JwtBundle':
        """Returns a new immutable snapshot of the current bundle contents."""
        return JwtBundle(self._trust_domain, self._jwt_authorities)