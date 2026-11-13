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

import json

import jwt
import pytest
from typing import Dict
from pytest_mock import MockerFixture
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import InvalidKeyError
from spiffe.bundle.jwt_bundle.jwt_bundle import JwtBundle, _PUBLIC_KEY_TYPES
from spiffe.bundle.jwt_bundle.errors import ParseJWTBundleError
from spiffe.errors import ArgumentError
from spiffe.spiffe_id.spiffe_id import TrustDomain, TrustDomainError
from spiffe.svid.jwt_svid import JwtSvid
from testutils.jwt import (
    JWKS_1_EC_KEY,
    JWKS_2_EC_1_RSA_KEYS,
    JWKS_MISSING_X,
    JWKS_MISSING_KEY_ID,
    TEST_AUDIENCE,
)

# Default trust domain to run test cases.
trust_domain = TrustDomain("spiffe://any.domain")

# Default authorities to run test cases.
ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
authorities: Dict[str, _PUBLIC_KEY_TYPES] = {
    'kid1': ec_key.public_key(),
    'kid2': rsa_key.public_key(),
}


def test_create_jwt_bundle() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    assert jwt_bundle.trust_domain == trust_domain
    assert len(jwt_bundle.jwt_authorities.keys()) == len(authorities.keys())


def test_create_jwt_bundle_no_authorities() -> None:
    jwt_bundle = JwtBundle(trust_domain, {})

    assert jwt_bundle.trust_domain == trust_domain
    assert isinstance(jwt_bundle.jwt_authorities, dict)
    assert len(jwt_bundle.jwt_authorities.keys()) == 0


def test_get_jwt_authority_valid_input() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    authority_key = jwt_bundle.get_jwt_authority('kid2')

    assert rsa_key.public_key() == authority_key


def test_get_jwt_authority_invalid_key_id_not_found() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    response = jwt_bundle.get_jwt_authority('p0')

    assert response is None


def test_get_jwt_authority_invalid_input() -> None:
    jwt_bundle = JwtBundle(trust_domain, authorities)

    with pytest.raises(ArgumentError) as exception:
        jwt_bundle.get_jwt_authority('')

    assert str(exception.value) == 'key_id cannot be empty'


def test_get_jwt_authority_empty_authority_dict() -> None:
    invalid_authorities: Dict[str, _PUBLIC_KEY_TYPES] = {}
    jwt_bundle = JwtBundle(trust_domain, invalid_authorities)

    response = jwt_bundle.get_jwt_authority(key_id='p1')

    assert response is None


@pytest.mark.parametrize(
    'test_bytes, expected_authorities',
    [(JWKS_1_EC_KEY, 1), (JWKS_2_EC_1_RSA_KEYS, 3)],
)
def test_parse(test_bytes: bytes, expected_authorities: int) -> None:
    jwt_bundle = JwtBundle.parse(trust_domain, test_bytes)

    assert jwt_bundle
    assert len(jwt_bundle.jwt_authorities) == expected_authorities


def test_parse_invalid_trust_domain() -> None:
    with pytest.raises(TrustDomainError) as exception:
        TrustDomain('')

    assert str(exception.value) == 'Invalid trust domain: cannot be empty'


def test_parse_missing_bundle_bytes() -> None:
    with pytest.raises(ArgumentError) as exception:
        JwtBundle.parse(trust_domain, b'')

    assert str(exception.value) == 'Bundle bytes cannot be empty'


@pytest.mark.parametrize(
    'test_bytes',
    [b'1211', b'invalid bytes'],
)
def test_parse_invalid_bytes(test_bytes: bytes) -> None:
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, test_bytes)

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: "bundle_bytes" does not represent a valid jwks'
    )


def test_parse_bundle_bytes_invalid_key(mocker: MockerFixture) -> None:
    mocker.patch(
        'spiffe.bundle.jwt_bundle.jwt_bundle.PyJWKSet.from_json',
        side_effect=InvalidKeyError('Invalid Key'),
        autospec=True,
    )

    with pytest.raises(ParseJWTBundleError) as err:
        JwtBundle.parse(trust_domain, JWKS_MISSING_X)

    assert str(err.value) == 'Error parsing JWT bundle: Invalid Key'


def test_parse_corrupted_key_missing_key_id() -> None:
    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, JWKS_MISSING_KEY_ID)

    assert (
        str(exception.value)
        == 'Error parsing JWT bundle: Error adding authority from JWKS: "keyID" cannot be empty'
    )


def test_parse_jwks_with_empty_keys_array() -> None:
    jwks_empty_keys_bytes = '{"keys": []}'.encode('utf-8')
    bundle = JwtBundle.parse(trust_domain, jwks_empty_keys_bytes)

    assert bundle
    assert len(bundle.jwt_authorities) == 0


def test_parse_jwks_with_null_keys_field() -> None:
    jwks_null_keys_bytes = '{"keys": null}'.encode('utf-8')
    bundle = JwtBundle.parse(trust_domain, jwks_null_keys_bytes)

    assert bundle
    assert len(bundle.jwt_authorities) == 0


def _rsa_jwk(private_key: rsa.RSAPrivateKey, key_id: str) -> dict:
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk['kid'] = key_id
    return jwk


def _jwks_bytes(keys: list) -> bytes:
    return json.dumps({'keys': keys}).encode('utf-8')


def test_parse_duplicate_kid_same_key_is_deduplicated_regardless_of_order() -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = _rsa_jwk(signing_key, 'shared-kid')

    bundle_first = JwtBundle.parse(trust_domain, _jwks_bytes([jwk, dict(jwk)]))
    bundle_reversed = JwtBundle.parse(trust_domain, _jwks_bytes([dict(jwk), jwk]))

    assert bundle_first == bundle_reversed
    assert set(bundle_first.jwt_authorities.keys()) == {'shared-kid'}
    assert bundle_first.get_jwt_authority('shared-kid') == signing_key.public_key()


def test_parse_duplicate_kid_conflicting_keys_fails_the_whole_update() -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    conflicting_jwks = _jwks_bytes(
        [_rsa_jwk(signing_key, 'shared-kid'), _rsa_jwk(other_key, 'shared-kid')]
    )

    with pytest.raises(ParseJWTBundleError) as exception:
        JwtBundle.parse(trust_domain, conflicting_jwks)

    error_message = str(exception.value)
    assert 'shared-kid' in error_message
    # Diagnostics identify the key by its kid only and never leak key material.
    assert 'BEGIN' not in error_message
    assert 'n":' not in error_message


def test_parse_duplicate_kid_conflict_is_order_independent() -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first_jwk = _rsa_jwk(signing_key, 'shared-kid')
    second_jwk = _rsa_jwk(other_key, 'shared-kid')

    with pytest.raises(ParseJWTBundleError):
        JwtBundle.parse(trust_domain, _jwks_bytes([first_jwk, second_jwk]))
    with pytest.raises(ParseJWTBundleError):
        JwtBundle.parse(trust_domain, _jwks_bytes([second_jwk, first_jwk]))


def test_parse_reordered_jwks_verify_the_same_signed_jwt_svid() -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_jwk = _rsa_jwk(signing_key, 'signing-kid')
    other_jwk = _rsa_jwk(other_key, 'other-kid')

    token = jwt.encode(
        {
            'aud': list(TEST_AUDIENCE),
            'sub': 'spiffe://any.domain/workload',
            'exp': 9999999999,
        },
        signing_key,
        algorithm='RS256',
        headers={'typ': 'JWT', 'kid': 'signing-kid'},
    )

    bundle = JwtBundle.parse(trust_domain, _jwks_bytes([other_jwk, signing_jwk]))
    reordered_bundle = JwtBundle.parse(
        trust_domain, _jwks_bytes([signing_jwk, other_jwk])
    )

    svid = JwtSvid.parse_and_validate(token, bundle, TEST_AUDIENCE)
    reordered_svid = JwtSvid.parse_and_validate(token, reordered_bundle, TEST_AUDIENCE)

    assert svid.spiffe_id == reordered_svid.spiffe_id
    assert svid.audience == reordered_svid.audience
