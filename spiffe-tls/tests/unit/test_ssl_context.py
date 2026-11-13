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

from typing import Tuple
from unittest.mock import MagicMock, patch
import warnings

import pytest
from OpenSSL import SSL
from cryptography.hazmat.primitives import serialization

from spiffe import X509Source, X509Svid, TrustDomain, X509Bundle, X509BundleSet
from spiffe.workloadapi.x509_context import X509Context
from spiffetls import create_ssl_context
from testutils.certs import TEST_BUNDLE_CERTS_DIR
from testutils.certs import TEST_CERTS_DIR


@pytest.fixture
def source_mocks() -> Tuple[MagicMock, X509Context]:
    der_type = serialization.Encoding.DER
    chain_path = TEST_CERTS_DIR / '1-chain.der'
    key_path = TEST_CERTS_DIR / '1-key.der'
    x509_svid = X509Svid.load(str(chain_path), str(key_path), der_type)

    bundle_1 = X509Bundle.load(
        TrustDomain('domain.test'), TEST_BUNDLE_CERTS_DIR / 'certs.der', der_type
    )
    bundle_2 = X509Bundle.load(
        TrustDomain('example.org'),
        TEST_BUNDLE_CERTS_DIR / 'federated_bundle.der',
        der_type,
    )
    x509_bundle_set = X509BundleSet.of([bundle_1, bundle_2])
    x509_context = X509Context([x509_svid], x509_bundle_set)

    x509_source_mock = MagicMock(spec=X509Source)
    x509_source_mock.get_x509_context.return_value = x509_context

    return x509_source_mock, x509_context


@pytest.mark.parametrize(
    "method,use_system_trust_store",
    [
        (SSL.TLS_SERVER_METHOD, False),
        (SSL.TLS_CLIENT_METHOD, False),
        (SSL.TLS_CLIENT_METHOD, True),
    ],
)
def test_create_ssl_context(
    method: int,
    use_system_trust_store: bool,
    source_mocks: Tuple[MagicMock, X509Context],
) -> None:
    authorize_fn = MagicMock()
    x509_source, x509_context = source_mocks
    with patch('OpenSSL.SSL.Context') as MockContext:
        ssl_context_instance = MockContext.return_value

        create_ssl_context(
            method,
            x509_source,
            authorize_fn,
            use_system_trusted_cas=use_system_trust_store,
        )

        MockContext.assert_called_once_with(method)
        ssl_context_instance.use_certificate.assert_called_once()
        ssl_context_instance.use_privatekey.assert_called_once()
        ssl_context_instance.check_privatekey.assert_called_once()

        if use_system_trust_store:
            ssl_context_instance.set_default_verify_paths.assert_called_once()
        else:
            ssl_context_instance.set_default_verify_paths.assert_not_called()

        # The whole configuration is built from a single coherent X509Context snapshot...
        x509_source.get_x509_context.assert_called_once()
        # ...and the deprecated split accessors must never be used.
        x509_source.svid.assert_not_called()
        x509_source.bundles.assert_not_called()
        assert x509_context.default_svid.spiffe_id is not None


def test_create_ssl_context_emits_no_deprecation_warning(
    source_mocks: Tuple[MagicMock, X509Context],
) -> None:
    x509_source, _ = source_mocks

    with warnings.catch_warnings(record=True) as warnings_record:
        warnings.simplefilter("always")
        create_ssl_context(SSL.TLS_CLIENT_METHOD, x509_source)

    deprecation_warnings = [
        str(w.message) for w in warnings_record if issubclass(w.category, DeprecationWarning)
    ]
    assert not deprecation_warnings, deprecation_warnings
