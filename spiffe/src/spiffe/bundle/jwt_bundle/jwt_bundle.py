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
JwtBundle module manages JwtBundle objects.
"""

from json import JSONDecodeError
from types import MappingProxyType
from typing import TYPE_CHECKING, Dict, Mapping, Optional, Union

from jwt.api_jwk import PyJWKSet
from jwt.exceptions import InvalidKeyError, PyJWKSetError
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448
from cryptography.hazmat.primitives import serialization

from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.bundle.jwt_bundle.errors import JwtBundleError, ParseJWTBundleError
from spiffe.errors import ArgumentError

JWT_PUBLIC_KEY_TYPES = Union[
    dsa.DSAPublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
]

# Backwards-compatible private alias used by existing callers/tests.
_PUBLIC_KEY_TYPES = JWT_PUBLIC_KEY_TYPES

__all__ = ['JwtBundle', 'JWT_PUBLIC_KEY_TYPES']

if TYPE_CHECKING:
    from spiffe.bundle.jwt_bundle.jwt_bundle_builder import JwtBundleBuilder


class JwtBundle(object):
    """Represents an immutable JWT Bundle.

    JwtBundle is a snapshot of trusted JWT public keys for a trust domain. The
    authority mapping cannot be changed after construction. Use
    :class:`~spiffe.bundle.jwt_bundle.jwt_bundle_builder.JwtBundleBuilder` to
    construct or update a bundle.
    """

    __slots__ = ('_trust_domain', '_jwt_authorities', '_authorities_fingerprint')

    def __init__(
        self,
        trust_domain: TrustDomain,
        jwt_authorities: Optional[Mapping[str, JWT_PUBLIC_KEY_TYPES]] = None,
    ) -> None:
        """Creates an immutable JwtBundle instance.

        Args:
            trust_domain: The TrustDomain to associate with the JwtBundle instance.
            jwt_authorities: A mapping with key_id -> PublicKey valid for the given
                TrustDomain. It is copied.

        Raises:
            JwtBundleError: In case the trust_domain is empty.
        """

        if not trust_domain:
            raise JwtBundleError("Trust domain cannot be empty")

        object.__setattr__(self, '_trust_domain', trust_domain)
        authorities = dict(jwt_authorities) if jwt_authorities else {}
        object.__setattr__(
            self,
            '_jwt_authorities',
            MappingProxyType(authorities),
        )
        object.__setattr__(
            self,
            '_authorities_fingerprint',
            _authorities_fingerprint(authorities),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f'{type(self).__name__} is immutable')

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f'{type(self).__name__} is immutable')

    @property
    def trust_domain(self) -> TrustDomain:
        """Returns the trust domain of the bundle."""
        return self._trust_domain

    @property
    def jwt_authorities(self) -> Mapping[str, JWT_PUBLIC_KEY_TYPES]:
        """Returns an immutable view of the JWT authorities in the bundle."""
        return self._jwt_authorities

    @classmethod
    def builder(
        cls,
        trust_domain: TrustDomain,
        jwt_authorities: Optional[Mapping[str, JWT_PUBLIC_KEY_TYPES]] = None,
    ) -> 'JwtBundleBuilder':
        """Creates a builder for constructing or updating a JWT bundle."""
        from spiffe.bundle.jwt_bundle.jwt_bundle_builder import JwtBundleBuilder

        return JwtBundleBuilder(trust_domain, jwt_authorities)

    def get_jwt_authority(self, key_id: Optional[str]) -> Optional[JWT_PUBLIC_KEY_TYPES]:
        """Returns the authority for the specified key_id.

        Args:
            key_id: Key id of the token to return the correspondent authority.

        Returns:
            The authority associated with the supplied key_id.
            None if the key_id is not found.

        Raises:
            ArgumentError: When key_id is not valid (empty or None).
        """
        if not key_id:
            raise ArgumentError('key_id cannot be empty')

        return self._jwt_authorities.get(key_id)

    @classmethod
    def parse(cls, trust_domain: TrustDomain, bundle_bytes: bytes) -> 'JwtBundle':
        """Parses a bundle from bytes. The data must be a standard RFC 7517 JWKS document.

        Args:
            trust_domain: A TrustDomain to associate to the bundle.
            bundle_bytes: An array of bytes that represents a set of JWKs.

        Returns:
            An instance of 'JWTBundle' with the JWT authorities associated to the given trust domain.

        Raises:
            ArgumentError: In case the trust_domain is empty or bundle_bytes is empty.
            ParseJWTBundleError: In case the set of jwt_authorities cannot be parsed from the bundle_bytes.
        """

        if not trust_domain:
            raise ArgumentError("Trust domain cannot be empty")

        if not bundle_bytes:
            raise ArgumentError('Bundle bytes cannot be empty')

        try:
            jwks = PyJWKSet.from_json(bundle_bytes.decode('utf-8'))

            jwt_authorities: Dict[str, JWT_PUBLIC_KEY_TYPES] = {}
            for jwk in jwks.keys:
                if not jwk.key_id:
                    raise ParseJWTBundleError(
                        'Error adding authority from JWKS: "keyID" cannot be empty'
                    )

                jwt_authorities[jwk.key_id] = jwk.key

            return JwtBundle(trust_domain, jwt_authorities)
        except InvalidKeyError as err:
            raise ParseJWTBundleError(str(err)) from err
        except PyJWKSetError as err:
            if str(err) == "The JWK Set did not contain any keys":
                return JwtBundle(trust_domain, {})
            else:
                raise ParseJWTBundleError(
                    '"bundle_bytes" does not represent a valid jwks'
                ) from err
        except (JSONDecodeError, AttributeError) as err:
            raise ParseJWTBundleError(
                '"bundle_bytes" does not represent a valid jwks'
            ) from err

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, JwtBundle):
            return False
        return (
            self._trust_domain == o._trust_domain
            and self._authorities_fingerprint == o._authorities_fingerprint
        )

    def __hash__(self) -> int:
        return hash((self._trust_domain, self._authorities_fingerprint))


def _authorities_fingerprint(
    authorities: Mapping[str, JWT_PUBLIC_KEY_TYPES],
) -> tuple[tuple[str, bytes], ...]:
    """Returns canonical key material independent of mapping order."""
    return tuple(
        (
            key_id,
            authorities[key_id].public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        for key_id in sorted(authorities)
    )

