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

import threading
from collections.abc import Callable
from typing import Any, cast
from unittest.mock import patch

import pytest

from spiffe import JwtBundle, JwtBundleSet, X509Bundle, X509BundleSet, X509Svid
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.workloadapi.errors import JwtSourceError, WorkloadApiError, X509SourceError
from spiffe.workloadapi.jwt_source import JwtSource
from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.x509_context import X509Context
from spiffe.workloadapi.x509_source import X509Source
from testutils.certs import BUNDLE, CHAIN1, KEY1
from testutils.jwt import JWKS_1_EC_KEY

# Safety net for event waits. Passing runs never wait this long: every
# synchronization point below is an event controlled by the test, not a sleep.
EVENT_TIMEOUT = 5


class _StreamHandle:
    """Cancel handler for one fake stream, driven entirely by events."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.cancel_count = 0
        self.on_success: Callable[[Any], None] | None = None
        self.update_on_release: Any = None

    def cancel(self) -> None:
        self.cancel_count += 1
        self.cancelled.set()


class _FakeWorkloadApiClient:
    """Fake WorkloadApiClient whose streams are gated by events instead of sleeps.

    Each stream call appends a handle to `x509_streams`/`jwt_streams` so tests
    can hold the call before it returns its cancel handler, inject updates,
    and count cancellations.
    """

    def __init__(
        self,
        *,
        x509_context: X509Context | None = None,
        jwt_bundle_set: JwtBundleSet | None = None,
        hold_x509_stream: bool = False,
        hold_jwt_stream: bool = False,
    ) -> None:
        self.x509_streams: list[_StreamHandle] = []
        self.jwt_streams: list[_StreamHandle] = []
        self.x509_stream_entered = threading.Event()
        self.jwt_stream_entered = threading.Event()
        self.close_count = 0
        self._x509_context = x509_context
        self._jwt_bundle_set = jwt_bundle_set
        self._hold_x509_stream = hold_x509_stream
        self._hold_jwt_stream = hold_jwt_stream

    def stream_x509_contexts(
        self,
        on_success: Callable[[X509Context], None],
        on_error: Callable[[Exception], None],
    ) -> _StreamHandle:
        stream = self._new_stream(self.x509_streams, self.x509_stream_entered, on_success)
        if self._x509_context is not None:
            on_success(self._x509_context)
        self._deliver_after_hold(stream, self._hold_x509_stream)
        return stream

    def stream_jwt_bundles(
        self,
        on_success: Callable[[JwtBundleSet], None],
        on_error: Callable[[Exception], None],
    ) -> _StreamHandle:
        stream = self._new_stream(self.jwt_streams, self.jwt_stream_entered, on_success)
        if self._jwt_bundle_set is not None:
            on_success(self._jwt_bundle_set)
        self._deliver_after_hold(stream, self._hold_jwt_stream)
        return stream

    def close(self) -> None:
        self.close_count += 1

    @staticmethod
    def _new_stream(
        streams: list[_StreamHandle],
        entered: threading.Event,
        on_success: Callable[[Any], None],
    ) -> _StreamHandle:
        stream = _StreamHandle()
        stream.on_success = on_success
        streams.append(stream)
        entered.set()
        return stream

    @staticmethod
    def _deliver_after_hold(stream: _StreamHandle, hold: bool) -> None:
        if hold:
            # Park the watcher thread until the test releases it, simulating a
            # Workload API that returns the cancel handler only after a delay.
            stream.release.wait(timeout=EVENT_TIMEOUT)
        if stream.update_on_release is not None and stream.on_success is not None:
            stream.on_success(stream.update_on_release)


def make_x509_context() -> X509Context:
    svid = X509Svid.parse_raw(CHAIN1, KEY1)
    bundle = X509Bundle.parse_raw(TrustDomain('example.org'), BUNDLE)
    return X509Context([svid], X509BundleSet.of([bundle]))


def make_jwt_bundle_set() -> JwtBundleSet:
    bundle = JwtBundle.parse(TrustDomain('domain.test'), JWKS_1_EC_KEY)
    return JwtBundleSet.of([bundle])


def test_x509_source_init_timeout_cancels_handler_returned_after_close() -> None:
    fake_client = _FakeWorkloadApiClient(hold_x509_stream=True)
    raised: list[X509SourceError] = []

    def construct() -> None:
        with patch(
            'spiffe.workloadapi.x509_source.WorkloadApiClient', return_value=fake_client
        ):
            try:
                X509Source(timeout_in_seconds=0.1)
            except X509SourceError as err:
                raised.append(err)

    constructor = threading.Thread(target=construct)
    constructor.start()

    # The watcher thread is parked inside the stream call, so the
    # initialization timeout closes the source before any cancel handler exists.
    assert fake_client.x509_stream_entered.wait(timeout=EVENT_TIMEOUT)
    constructor.join(timeout=EVENT_TIMEOUT)
    assert not constructor.is_alive()
    assert len(raised) == 1
    assert 'Timeout waiting for the first update' in str(raised[0])
    assert fake_client.close_count == 1
    stream = fake_client.x509_streams[0]
    assert not stream.cancelled.is_set()

    # The late handler is cancelled exactly once, and the owned client is not
    # closed a second time.
    stream.release.set()
    assert stream.cancelled.wait(timeout=EVENT_TIMEOUT)
    assert stream.cancel_count == 1
    assert fake_client.close_count == 1


def test_jwt_source_init_timeout_cancels_handler_returned_after_close() -> None:
    fake_client = _FakeWorkloadApiClient(hold_jwt_stream=True)
    raised: list[JwtSourceError] = []

    def construct() -> None:
        with patch(
            'spiffe.workloadapi.jwt_source.WorkloadApiClient', return_value=fake_client
        ):
            try:
                JwtSource(timeout_in_seconds=0.1)
            except JwtSourceError as err:
                raised.append(err)

    constructor = threading.Thread(target=construct)
    constructor.start()

    # The watcher thread is parked inside the stream call, so the
    # initialization timeout closes the source before any cancel handler exists.
    assert fake_client.jwt_stream_entered.wait(timeout=EVENT_TIMEOUT)
    constructor.join(timeout=EVENT_TIMEOUT)
    assert not constructor.is_alive()
    assert len(raised) == 1
    assert 'Timeout waiting for the first update' in str(raised[0])
    assert fake_client.close_count == 1
    stream = fake_client.jwt_streams[0]
    assert not stream.cancelled.is_set()

    # The late handler is cancelled exactly once, and the owned client is not
    # closed a second time.
    stream.release.set()
    assert stream.cancelled.wait(timeout=EVENT_TIMEOUT)
    assert stream.cancel_count == 1
    assert fake_client.close_count == 1


def test_x509_source_close_from_subscriber_callback_on_watcher_thread() -> None:
    fake_client = _FakeWorkloadApiClient(
        x509_context=make_x509_context(), hold_x509_stream=True
    )
    with patch('spiffe.workloadapi.x509_source.WorkloadApiClient', return_value=fake_client):
        source = X509Source(timeout_in_seconds=EVENT_TIMEOUT)

    stream = fake_client.x509_streams[0]
    callback_done = threading.Event()

    def close_from_callback() -> None:
        source.close()
        callback_done.set()

    source.subscribe_for_updates(close_from_callback)

    # The watcher thread is still parked inside the stream call; releasing it
    # makes it deliver this update synchronously, so close() runs on the
    # source's own watcher thread. A close() that waited for that thread to
    # finish would deadlock here and the event would never be set.
    stream.update_on_release = make_x509_context()
    stream.release.set()

    assert callback_done.wait(timeout=EVENT_TIMEOUT)
    assert stream.cancelled.wait(timeout=EVENT_TIMEOUT)
    assert source.is_closed()
    assert stream.cancel_count == 1
    assert fake_client.close_count == 1
    with pytest.raises(X509SourceError, match='source is closed'):
        source.get_x509_context()

    # A late update neither resurrects the source nor re-runs the cleanup,
    # even though it triggers the subscriber callback that closes again.
    assert stream.on_success is not None
    stream.on_success(make_x509_context())
    assert source.is_closed()
    with pytest.raises(X509SourceError, match='source is closed'):
        source.get_x509_context()

    source.close()
    source._on_error(WorkloadApiError('late error'))
    assert stream.cancel_count == 1
    assert fake_client.close_count == 1


def test_jwt_source_close_from_subscriber_callback_on_watcher_thread() -> None:
    fake_client = _FakeWorkloadApiClient(
        jwt_bundle_set=make_jwt_bundle_set(), hold_jwt_stream=True
    )
    with patch('spiffe.workloadapi.jwt_source.WorkloadApiClient', return_value=fake_client):
        source = JwtSource(timeout_in_seconds=EVENT_TIMEOUT)

    stream = fake_client.jwt_streams[0]
    callback_done = threading.Event()

    def close_from_callback() -> None:
        source.close()
        callback_done.set()

    source.subscribe_for_updates(close_from_callback)

    # The watcher thread is still parked inside the stream call; releasing it
    # makes it deliver this update synchronously, so close() runs on the
    # source's own watcher thread. A close() that waited for that thread to
    # finish would deadlock here and the event would never be set.
    stream.update_on_release = make_jwt_bundle_set()
    stream.release.set()

    assert callback_done.wait(timeout=EVENT_TIMEOUT)
    assert stream.cancelled.wait(timeout=EVENT_TIMEOUT)
    assert source.is_closed()
    assert stream.cancel_count == 1
    assert fake_client.close_count == 1
    with pytest.raises(JwtSourceError, match='source is closed'):
        _ = source.bundles

    # A late update neither resurrects the source nor re-runs the cleanup,
    # even though it triggers the subscriber callback that closes again.
    assert stream.on_success is not None
    stream.on_success(make_jwt_bundle_set())
    assert source.is_closed()
    with pytest.raises(JwtSourceError, match='source is closed'):
        _ = source.bundles

    source.close()
    source._on_error(WorkloadApiError('late error'))
    assert stream.cancel_count == 1
    assert fake_client.close_count == 1


def test_x509_and_jwt_sources_sharing_a_client_close_independently() -> None:
    fake_client = _FakeWorkloadApiClient(
        x509_context=make_x509_context(), jwt_bundle_set=make_jwt_bundle_set()
    )
    client = cast(WorkloadApiClient, fake_client)
    x509_source = X509Source(client)
    jwt_source = JwtSource(client)

    jwt_updated = threading.Event()
    jwt_source.subscribe_for_updates(lambda: jwt_updated.set())

    # Closing the X509 source cancels only its own stream; the shared client
    # is externally owned, so it is not closed.
    x509_source.close()
    assert fake_client.x509_streams[0].cancel_count == 1
    assert fake_client.jwt_streams[0].cancel_count == 0
    assert fake_client.close_count == 0

    # The JWT source keeps receiving updates through the shared client.
    jwt_on_success = fake_client.jwt_streams[0].on_success
    assert jwt_on_success is not None
    jwt_on_success(make_jwt_bundle_set())
    assert jwt_updated.wait(timeout=EVENT_TIMEOUT)
    assert not jwt_source.is_closed()
    assert jwt_source.get_bundle_for_trust_domain(TrustDomain('domain.test')) is not None

    # A late update does not resurrect the closed X509 source.
    x509_on_success = fake_client.x509_streams[0].on_success
    assert x509_on_success is not None
    x509_on_success(make_x509_context())
    assert x509_source.is_closed()
    with pytest.raises(X509SourceError, match='source is closed'):
        x509_source.get_x509_context()

    # Closing the JWT source cancels its stream but still not the client.
    jwt_source.close()
    assert fake_client.jwt_streams[0].cancel_count == 1
    assert fake_client.close_count == 0

    # The shared client remains usable for new sources; the owner closes it.
    with JwtSource(client) as new_jwt_source:
        assert not new_jwt_source.is_closed()
        bundle = new_jwt_source.get_bundle_for_trust_domain(TrustDomain('domain.test'))
        assert bundle is not None
    assert fake_client.jwt_streams[1].cancel_count == 1
    assert fake_client.close_count == 0

    client.close()
    assert fake_client.close_count == 1
