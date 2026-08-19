# CodexWatch

CodexWatch is a Linux-only passive monitor for Codex Responses traffic. It does not change Codex configuration, proxy model requests, use app-server, install Codex hooks, or poll rollout files.

## Components

- `codexwatch-client`: privileged capture daemon, local 72-hour content store, durable summary outbox, and server command poller.
- `codexwatch-server`: Axum/SQLite ingest and query service with on-demand content requests.
- `codexwatch-protocol`: versioned CBOR contracts and lifecycle validation shared by client and server.
- `codexwatch-capture`: TCP, HTTP/1.1, HTTP/2, WebSocket, SSE, and Responses decoding.
- `codexwatch-profile` and `codexwatch-capture-ebpf`: build-profile validation and Aya probe ABI/programs.

## Build

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --workspace
cargo test --workspace
```

The eBPF target has a separate build path documented in `docs/PROBE_PROFILES.md`. Normal host builds do not require a BPF target.

## Runtime Data

Client metadata is stored in `/var/lib/codexwatch-client/client.db`; sanitized complete request/response blobs are content-addressed below `/var/lib/codexwatch-client/content` and expire after 72 hours. Routine uploads contain no prompt, tool, or model text.

Server metadata is stored in `/var/lib/codexwatch-server/server.db`. Full content reaches the server only after a content request and is retained for the 30 most recently requested native session/thread conversations per client.

Copy the service units from `deploy/systemd`, install the generated binaries in `/usr/local/bin`, and place environment files under `/etc/codexwatch`. The client unit runs as root because AF_PACKET and eBPF attachment require privileged kernel access on the target Linux 5.15 host.

## Capture Support

Plain HTTP uses AF_PACKET and PID/socket attribution. HTTPS and internal Codex terminal events require a profile whose ELF hash, probe offsets, ABI layout, and instruction signatures all validate. Unknown or placeholder profiles produce `unsupported_codex_build`; they are never attached speculatively.

See `docs/TECH_SPEC.md` for the protocol and persistence invariants.
