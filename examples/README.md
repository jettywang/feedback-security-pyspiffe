# Examples

The repo includes manual smoke tests exposed as `uv` entry points. They are not
part of CI and are not production examples.

Available commands:

```bash
uv run --package py-spiffe-examples mtls-smoke-server --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples mtls-smoke-client --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples httpx-stdlib-mtls-client --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples workload-failure-demo
```

`mtls-smoke-server` and `mtls-smoke-client` validate:
- Workload API connectivity
- X.509 SVID rotation
- reconnect behavior after SPIRE Agent restarts
- mTLS authorization

`httpx-stdlib-mtls-client` validates:
- `SpiffeSSLContext` integration with `httpx`
- stdlib TLS compatibility
- certificate refresh behavior

`workload-failure-demo` runs offline and validates:
- py-spiffe retry/backoff behavior for transient and permanent Workload API errors
- separate retention rules for the local SVID and federated trust bundles
- local SVID expiry, trust-root removal, and already-established connection boundaries
- real pyOpenSSL handshakes over memory BIOs (no sockets, no SPIRE)

See `src/py_spiffe_examples/workload_failure_demo/README.md` for the policy
comparison and parameter rationale.

Prerequisites (`workload-failure-demo` needs none of these):
- SPIRE Agent running and reachable
- `SPIFFE_ENDPOINT_SOCKET` set to the Workload API socket
- workload registration configured in SPIRE

Typical flow:

```bash
export SPIFFE_ENDPOINT_SOCKET=/tmp/agent.sock
uv run --package py-spiffe-examples mtls-smoke-server --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples mtls-smoke-client --host 127.0.0.1 --port 8443 --path /health
uv run --package py-spiffe-examples httpx-stdlib-mtls-client --host 127.0.0.1 --port 8443 --path /health
```

Useful flags:
- `--debug` for verbose tracebacks
- `--authorize <spiffe-id>` on `mtls-smoke-server` to override the default
  self-authorization policy
- `--interval`, `--timeout`, and `--source-timeout` on the clients to tune
  polling and startup behavior

Common failure modes:
- Workload API fetch failures usually mean the agent is unavailable, the socket
  path is wrong, or the workload is not registered correctly.
- TLS verification failures usually mean the presented SPIFFE ID does not match
  the server authorization policy or the trust bundle is not configured the way
  you expect.
