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

Offline, self-contained gRPC fixtures for the Workload API client.

These tests spin up a minimal in-process SPIFFE Workload API gRPC server bound
to a freshly created Unix domain socket. The server lives only for the duration
of the test that owns it: there is no SPIRE dependency, no fixed port, and no
manual setup.

Synchronization between the server and the client watcher is event/queue based.
The tests never sleep to wait for an outcome, so running them repeatedly leaves
no listening socket or worker thread behind.
"""

from __future__ import annotations

import queue
import threading
from concurrent import futures
from pathlib import Path
from typing import Iterator, List, Tuple

import grpc
import pytest

from spiffe import SpiffeId, WorkloadApiClient
from spiffe._proto import workload_pb2, workload_pb2_grpc
from spiffe.spiffe_id.spiffe_id import TrustDomain
from spiffe.workloadapi.workload_api_client import (
    WORKLOAD_API_HEADER_KEY,
    WORKLOAD_API_HEADER_VALUE,
)
from spiffe.workloadapi.x509_context import X509Context
from testutils.certs import BUNDLE, CHAIN1, FEDERATED_BUNDLE, KEY1

_TRUST_DOMAIN = TrustDomain('example.org')
_REQUIRED_METADATA = (WORKLOAD_API_HEADER_KEY, WORKLOAD_API_HEADER_VALUE)
_MISSING_METADATA_DETAIL = 'missing required Workload API metadata'

# Sentinel pushed onto a response queue to unblock a streaming handler on shutdown.
_SHUTDOWN = object()


def _x509_svid_response(bundle: bytes) -> workload_pb2.X509SVIDResponse:
    """Builds a one-SVID X.509 response carrying the given trust bundle bytes."""
    return workload_pb2.X509SVIDResponse(
        svids=[
            workload_pb2.X509SVID(
                spiffe_id='spiffe://example.org/service',
                x509_svid=CHAIN1,
                x509_svid_key=KEY1,
                bundle=bundle,
            )
        ]
    )


class _OfflineWorkloadApiServicer(workload_pb2_grpc.SpiffeWorkloadAPIServicer):
    """Minimal Workload API server that enforces the required protocol metadata.

    Every RPC must carry the ``workload.spiffe.io: true`` metadata injected by
    the client interceptor. Requests without it are rejected with
    ``INVALID_ARGUMENT`` before any response is produced.
    """

    def __init__(self) -> None:
        # One queue per open stream; tests push responses to drive updates.
        self._streams: List['queue.Queue[object]'] = []
        self._streams_lock = threading.Lock()
        self.observed_metadata: List[Tuple[Tuple[str, str], ...]] = []
        self.first_call_started = threading.Event()

    def open_stream(self) -> 'queue.Queue[object]':
        stream: 'queue.Queue[object]' = queue.Queue()
        with self._streams_lock:
            self._streams.append(stream)
        return stream

    def close_streams(self) -> None:
        with self._streams_lock:
            streams = list(self._streams)
            self._streams.clear()
        for stream in streams:
            stream.put(_SHUTDOWN)

    def _require_metadata(self, context: grpc.ServicerContext) -> None:
        metadata = tuple(context.invocation_metadata() or ())
        self.observed_metadata.append(metadata)
        self.first_call_started.set()
        header = dict(metadata).get(WORKLOAD_API_HEADER_KEY)
        if header != WORKLOAD_API_HEADER_VALUE:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, _MISSING_METADATA_DETAIL)

    def FetchX509SVID(
        self,
        request: workload_pb2.X509SVIDRequest,
        context: grpc.ServicerContext,
    ) -> Iterator[workload_pb2.X509SVIDResponse]:
        del request
        self._require_metadata(context)

        stream = self.open_stream()
        terminated = threading.Event()
        context.add_callback(terminated.set)

        while not terminated.is_set():
            item = stream.get()
            if item is _SHUTDOWN or not context.is_active():
                return
            yield item  # type: ignore[misc]


class _OfflineWorkloadApiServer:
    """Owns the gRPC server, its worker pool, and the ephemeral UDS endpoint."""

    def __init__(self, socket_path: Path) -> None:
        self._socket_path = socket_path
        self.servicer = _OfflineWorkloadApiServicer()
        self._executor = futures.ThreadPoolExecutor(max_workers=4)
        # Force every worker thread to spin up and record its name through the
        # public executor API instead of reaching into its private thread set.
        barrier = threading.Barrier(4)
        self._worker_names = list(
            self._executor.map(lambda _: self._register_worker(barrier), range(4))
        )
        self._server = grpc.server(self._executor)
        workload_pb2_grpc.add_SpiffeWorkloadAPIServicer_to_server(  # type: ignore[no-untyped-call]
            self.servicer, self._server
        )
        self._server.add_insecure_port(f'unix:{socket_path}')

    @staticmethod
    def _register_worker(barrier: threading.Barrier) -> str:
        barrier.wait()
        return threading.current_thread().name

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    @property
    def worker_names(self) -> List[str]:
        return list(self._worker_names)

    def start(self) -> '_OfflineWorkloadApiServer':
        self._server.start()
        return self

    def stop(self) -> None:
        # Grace of zero cancels in-flight RPCs promptly, then the worker pool is
        # joined so no thread outlives the server.
        self.servicer.close_streams()
        self._server.stop(grace=None)
        self._executor.shutdown(wait=True)
        self._socket_path.unlink(missing_ok=True)


@pytest.fixture
def workload_api_server(tmp_path: Path) -> Iterator[_OfflineWorkloadApiServer]:
    socket_path = tmp_path / 'workload-api.sock'
    server = _OfflineWorkloadApiServer(socket_path).start()
    try:
        yield server
    finally:
        server.stop()


def _client_for(server: _OfflineWorkloadApiServer) -> WorkloadApiClient:
    return WorkloadApiClient(socket_path=f'unix://{server.socket_path}')


def _bundle_authority_subject(context: X509Context) -> str:
    bundle = context.x509_bundle_set.get_bundle_for_trust_domain(_TRUST_DOMAIN)
    assert bundle is not None
    (authority,) = tuple(bundle.x509_authorities)
    return authority.subject.rfc4514_string()


def test_unary_fetch_delivers_first_identity_with_required_metadata(
    workload_api_server: _OfflineWorkloadApiServer,
) -> None:
    workload_api_server.servicer.open_stream().put(_x509_svid_response(BUNDLE))

    with _client_for(workload_api_server) as client:
        svid = client.fetch_x509_svid()
        # Wait for the server to record the inbound metadata before asserting,
        # decoupling the check from response-processing timing.
        workload_api_server.servicer.first_call_started.wait(timeout=5)

    assert svid.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert svid.leaf is not None
    assert _REQUIRED_METADATA in workload_api_server.servicer.observed_metadata[0]


def test_stream_delivers_first_identity_then_bundle_update_and_cancels_silently(
    workload_api_server: _OfflineWorkloadApiServer,
) -> None:
    stream = workload_api_server.servicer.open_stream()
    stream.put(_x509_svid_response(BUNDLE))

    with _client_for(workload_api_server) as client:
        contexts: List[X509Context] = []
        errors: List[Exception] = []
        received = threading.Event()
        second_received = threading.Event()

        def on_success(context: X509Context) -> None:
            contexts.append(context)
            (second_received if len(contexts) == 2 else received).set()

        watcher_before = set(threading.enumerate())
        handler = client.stream_x509_contexts(on_success, errors.append)
        # The watcher is a plain threading.Thread; gRPC's own connection thread
        # carries a "(_run)" target name and is excluded so the selection cannot
        # race with channel setup.
        watcher = next(
            thread
            for thread in threading.enumerate()
            if thread not in watcher_before
            and thread is not threading.current_thread()
            and not thread.name.endswith('(_run)')
        )

        # First identity, synchronized via an event instead of sleeping.
        assert received.wait(timeout=5)
        assert contexts[0].default_svid.spiffe_id == SpiffeId('spiffe://example.org/service')
        first_subject = _bundle_authority_subject(contexts[0])

        # Subsequent bundle update: same SVID, rotated trust bundle.
        stream.put(_x509_svid_response(FEDERATED_BUNDLE))
        assert second_received.wait(timeout=5)
        assert len(contexts) == 2
        assert _bundle_authority_subject(contexts[1]) != first_subject
        assert errors == []

        handler.cancel()
        watcher.join(timeout=5)
        assert not watcher.is_alive()
        assert errors == []


def test_server_rejects_call_missing_protocol_metadata(
    workload_api_server: _OfflineWorkloadApiServer,
) -> None:
    workload_api_server.servicer.open_stream().put(_x509_svid_response(BUNDLE))

    # A raw channel without the header interceptor proves the server-side
    # assertion is what gates access, independent of the real client.
    raw_channel = grpc.insecure_channel(f'unix:{workload_api_server.socket_path}')
    raw_stub = workload_pb2_grpc.SpiffeWorkloadAPIStub(  # type: ignore[no-untyped-call]
        raw_channel
    )
    try:
        with pytest.raises(grpc.RpcError) as rpc_error:
            next(raw_stub.FetchX509SVID(workload_pb2.X509SVIDRequest()))
        assert rpc_error.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert rpc_error.value.details() == _MISSING_METADATA_DETAIL
    finally:
        raw_channel.close()


def test_real_client_attaches_metadata_that_passes_server_assertion(
    workload_api_server: _OfflineWorkloadApiServer,
) -> None:
    workload_api_server.servicer.open_stream().put(_x509_svid_response(BUNDLE))

    # The production client routes through the header interceptor, so it passes
    # the very assertion that rejects the raw, interceptor-less channel above.
    with _client_for(workload_api_server) as client:
        context = client.fetch_x509_context()

    assert context.default_svid.spiffe_id == SpiffeId('spiffe://example.org/service')
    assert _REQUIRED_METADATA in workload_api_server.servicer.observed_metadata[-1]


def test_running_twice_leaves_no_listener_or_worker_threads(
    tmp_path: Path,
) -> None:
    def run_once(socket_name: str) -> List[str]:
        socket_path = tmp_path / socket_name
        server = _OfflineWorkloadApiServer(socket_path).start()
        worker_names = server.worker_names
        server.servicer.open_stream().put(_x509_svid_response(BUNDLE))
        with _client_for(server) as client:
            svid = client.fetch_x509_svid()
            assert svid.spiffe_id == SpiffeId('spiffe://example.org/service')
        server.stop()
        return worker_names

    first_workers = run_once('first.sock')
    second_workers = run_once('second.sock')

    assert not (tmp_path / 'first.sock').exists()
    assert not (tmp_path / 'second.sock').exists()
    leftovers = [
        thread.name
        for thread in threading.enumerate()
        if thread.name in set(first_workers) | set(second_workers)
    ]
    assert leftovers == []
