# CodexWatch v1 Technical Specification

## Invariants

- CodexWatch never changes Codex `base_url`, proxies Codex requests, uses app-server, installs hooks, or polls rollout/session files.
- The Linux client captures Codex traffic out of process. Plain HTTP uses AF_PACKET; HTTPS uses build-profiled rustls uprobes.
- A Responses terminal event ends one model attempt. Only a validated Codex terminal event ends the complete turn.
- Capture loss, an unknown binary build, or an undecodable stream never becomes a fabricated success or failure.
- Routine ingest contains structured identity, state, error, usage, and completeness data only. It excludes prompt, tool, and model text.
- Full content remains on the client for 72 hours and is uploaded only after a server content request.
- Server full content is retained for the 30 most recently requested native Codex session/thread pairs per client.

## Runtime Model

The client identifies a task by `(client_id, provider, session_id, thread_id, turn_id)`. A task owns one or more transport attempts. Each state transition carries a UUIDv7 event ID and a monotonically increasing task sequence.

Task phases are `running`, `awaiting_tool`, `retrying`, and `terminal`. Terminal task outcomes are `completed`, `failed`, `aborted`, `terminated`, and `lost`. Attempt outcomes are independently `completed`, `failed`, `incomplete`, `cancelled`, and `transport_lost`. `response.failed`, `response.incomplete`, and `response.cancelled` end only the attempt; they leave the task retryable. Only validated `TurnComplete(error=None)`, `TurnComplete(error=Some)`, `TurnAborted`, or confirmed process termination can set a task outcome. Provider events and errors retain their original wire type and structured fields.

## Capture Model

AF_PACKET frames are attributed to a Codex process through process start identity, socket inode, and TCP five-tuple. TCP streams handle retransmission, overlap, reordering, FIN/RST, and bounded gaps. HTTPS plaintext and internal terminal events use uprobes selected by an exact ELF SHA-256 profile. A profile contains PIE-relative file offsets, argument layouts, masked instruction signatures, and connection create/drop/read/write plus terminal/error probe points that must match before attachment.

Every plaintext probe record contains `(boot_id, tgid, process_start_ticks, connection_ptr, connection_epoch, direction, call_sequence, captured_offset, captured_len, original_len)`. A validated create probe allocates `connection_epoch`; drop closes it. Thread ID and timestamp proximity are never connection identities. HTTP/2 stream IDs remain scoped to this connection identity.

A capture gap immediately changes observability to `degraded` but leaves a live task in its existing phase. It becomes `lost` only after client restart finds the owning process absent, or the process exits normally without a validated terminal event. A confirmed signal/nonzero process exit produces `terminated` with exit evidence. A connection close alone never terminates a task.

The protocol decoder accepts HTTP/1.1, HTTP/2 with HPACK, and WebSocket Responses traffic. It incrementally handles content encodings and SSE framing. Codex identity comes from `x-codex-turn-metadata` or the canonical `client_metadata["x-codex-turn-metadata"]` value. Only `request_kind=turn` creates a user task.

## Persistence And Delivery

The client stores reconstruction state, capture gaps, a durable summary outbox, command state, and raw-object metadata in SQLite. Content-addressed zstd blobs hold complete sanitized requests and responses for exactly 72 hours unless pinned by a live content command. Authorization, cookie, and API-key headers are removed before persistence. The summary outbox is capped at 1 GiB and reserves 64 MiB for terminal, error, gap, and heartbeat records; low-priority topology records are discarded first. Error messages are limited to 32 KiB with original length and SHA-256 retained when truncated.

The server stores client identity, sessions, tasks, attempts, exchanges, transitions, errors, gaps, health, receipts, content requests, and content-object links in SQLite. Ingest batches are versioned CBOR compressed with zstd, limited to 2 MiB after decompression, authenticated by a client-bound bearer token, and uniquely keyed by `(client_id, batch_id)`. The receipt stores `payload_sha256`; the same hash returns the original acknowledgement and a different hash returns 409 with no writes.

Clients long-poll the server command endpoint. Content requests identify a task and requested parts; unavailable content completes with an explicit `content_expired` result. Uploaded content is deduplicated by SHA-256. In one transaction, an accepted upload updates the conversation's `content_last_requested_at`, deletes content links for conversations outside the newest 30 per client, then garbage-collects unreferenced blobs without deleting task metadata.

Server retention is 365 days for session/task/status/error summaries, 180 days for exchanges/events/gaps, 30 days for heartbeat samples, and 400 days for ingest receipts. Active non-terminal tasks are excluded from retention cleanup.

## Acceptance

- Current Codex HTTP traffic is decoded without changing its configured destination.
- Test rustls HTTP/1.1, HTTP/2, and WebSocket streams are captured as plaintext.
- Tool turns create multiple attempts under one native `turn_id` and one terminal task transition.
- Completed, failed, incomplete, aborted, process-signal, capture-gap, and unknown-profile cases remain distinguishable.
- Offline delivery, duplicate batches, content expiry, and 30-conversation eviction are deterministic and tested.
- A repeated batch ID with a different hash returns 409; client-bound tokens cannot spoof client identity; decompressed bodies over 2 MiB are rejected before CBOR allocation completes.
- Routine ingest contains no prompt/tool/model text or captured credentials, and a failed attempt followed by a successful retry does not mark the task failed.
- Concurrent non-Codex traffic to the same destination is not attributed to Codex; concurrent TLS connections and interleaved HTTP/2 streams remain separate.
- Client restart, Codex SIGKILL, a capture gap while the process remains alive, and an unknown probe profile produce their specified degraded/terminated/lost states without a fabricated terminal event.
