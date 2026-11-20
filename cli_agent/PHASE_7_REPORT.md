# ForensIQ Phase 7 — Reliability, Lossless Delivery and Hardening

Date: 2026-11-19/20
Branch: `main` at `b00b6fa` (`fix: visuals`)
Scope implemented: `cli_agent/` only. No backend, frontend, docs, theme palette or theme architecture changes were made.

## 1. Repository state and baseline

- Starting tree: clean at `b00b6fa`; Phase 7 edits are intentionally uncommitted.
- Historical Phase 6 figure was 157 passing. The actual pre-Phase 7 baseline measured on this checkout was **170 passed** (theme work included).
- Local services used: MongoDB container `forensiq-mongo` (TLS, 127.0.0.1:27017) and FastAPI at `http://127.0.0.1:8000` (health 200).
- Final suite: **223 passed** (`cli_agent/.venv/bin/python -m pytest cli_agent/tests -q`, 50.29 s).
- Nothing was staged, committed, pushed, reset or cleaned. Existing runtime files under `~/.config/forensiq/` (including a pre-existing `pending_delivery.json`) were preserved and not read into this report.

## 2. Defects discovered

1. **Silent data loss in oversized cycles.** `fit_logs_to_backend` kept only the newest ~50k characters and inserted a truncation marker, so earlier collected events were discarded. This was the live Phase 6 failure.
2. **Checkpoint advanced before acknowledgement.** `CollectorService.collect()` persisted offsets as part of collection, before the backend accepted the data; a failed submission permanently skipped those events.
3. **Rotation detection depended on size only.** Replacing a log with a larger file at the same path was treated as "already read", skipping the replacement's initial bytes.
4. **No durable pending area.** An application exit or crash during a failed submission lost the collected-but-unsent cycle.
5. **Retry policy did not cover POST/analyze**, ignored `Retry-After`, and had no jitter or explicit 408/425/429 handling; a backend restart mid-submission failed the cycle immediately. Monitoring retried on the next polling interval only.
6. **Monitoring lifecycle races.** No generation/lifecycle lock; a new start after `ERROR` could overlap a still-unwinding old loop, repeated start/stop was not guarded, and a backend session was not closed when stop won a race with session creation.
7. **Session close status was optimistic.** The UI could report a session closed without confirmation.
8. **Authentication expiry left monitoring running.** A 401 during submission became a generic failure; the loop kept polling and the token stayed in place, producing a false running state.
9. **Configuration was mutable during monitoring**, and a corrupted config file prevented startup instead of surfacing a controlled fallback.
10. **Saved config was world-readable** (default file mode) rather than `0600`.
11. A storage-full journal could report a pending batch that was never durably written, and configuration temp-file cleanup could raise on an unset temp name.

## 3. Files changed

Modified:

- `cli_agent/services/limits.py` — lossless `split_logs_lossless` and `BatchSplit`; deprecated lossy helper retained for compatibility but unused by monitoring.
- `cli_agent/services/api_client.py` — response headers, jittered capped backoff, `Retry-After`, transient POST retries, injectable sleep.
- `cli_agent/services/errors.py` — `ApiError.retry_after`, `StatePersistenceError`.
- `cli_agent/services/collector_service.py` — deferred/ack-gated persistence, v2 state with file identity, corrupt-state quarantine, private atomic writes.
- `cli_agent/services/monitoring_service.py` — rewritten delivery loop, generation/lifecycle guards, journal, bounded stop, honest session close, new stats.
- `cli_agent/services/cli_service.py` — outbox wiring, config fallback (`config_error`), monitoring-active guards.
- `cli_agent/services/config_service.py` — URL scheme validation, atomic `0600` save, safe temp cleanup.
- `cli_agent/tui/state.py`, `cli_agent/tui/app.py` — status fields/lines only for pending batches, oversized batches, delivery attempts and session close. No layout, palette, navigation or theme logic changed.
- `cli_agent/tests/conftest.py` — FakeTransport supports response headers and delays.
- `cli_agent/tests/test_tui_pages.py` — truncation test replaced with a lossless two-batch assertion; six-page test at both official sizes.

New:

- `cli_agent/services/outbox.py`
- `cli_agent/tests/test_batching.py` (8), `test_outbox.py` (11), `test_delivery.py` (10), `test_api_reliability.py` (10), `test_collector_hardening.py` (7), `test_config_hardening.py` (5), plus 2 size-parametrised TUI cases = **53 new tests**.

## 4. Batching and delivery design

- Verified backend contract: `LogAnalysisRequest.logs` has `max_length=50000`; `max_results` is 1–20.
- The limit applies to the `logs` string, so batches are measured in characters, not JSON bytes.
- `split_logs_lossless` walks the text and prefers the last newline in the second half of each window. A single record larger than the limit is hard-cut across consecutive batches; no data is dropped and no marker is inserted. Whitespace-only fragments produce no batch.
- Consecutive batches are sent sequentially in original order through the existing `/api/v1/analyze` endpoint. Empty batches are never submitted.
- Only one delivery cycle can be pending at a time. While a journal exists, no new collection occurs, preventing concurrent duplicate submission and bounding disk/memory.
- TUI status shows submitted/pending batch counts, pending entries/bytes, delivery attempts and oversized-batch count using existing widgets.

## 5. Actual delivery guarantees and limitations

Guarantee: **at-least-once for successfully acknowledged batches**, with no silent loss.

- Batches are written to the journal before the first request.
- A batch is removed from the journal only after a successful backend response, and the collector checkpoint is committed only after every batch in that delivery is acknowledged.
- A crash or connection loss after the backend processed a request but before the client saw the response causes a resend → **possible duplicates**.
- A crash after the final acknowledgement but before the checkpoint write/clear also causes a resend → **possible duplicates**.
- No idempotency key exists in the backend contract, so **exactly-once is not claimed and not achievable client-side**.
- HTTP 500 is deliberately non-retryable for POST because the server may have processed the request; the batch remains pending and is observable rather than silently retried or dropped.
- Timeouts/transport failures on explicit transient retries can duplicate an already-processed submission. This is documented, not concealed.

## 6. Queue persistence and capacity

- Journal: one pending cycle in `pending_delivery.json` (sibling of the collector state by default; tests with stateless collectors create no file).
- Limits: **8 MiB** of JSON payload and **64 batches**. Older acked batches are not kept.
- Writes: same-directory temp file, `fsync`, `os.replace`, file `0600`, directory `0700`.
- Contents contain log text and metadata, no JWT or password. The journal is a sensitive local artifact and is kept private.
- Corruption: invalid JSON or malformed batches are quarantined as `pending.json.corrupt-<timestamp>` and surfaced as an error; nothing is deleted.
- Capacity/permission/full-disk failure: collection pauses with an ERROR status and a clear storage message. The checkpoint is not advanced, so the unread bytes remain available; data is never deleted to make room.

## 7. Checkpoint and restart behavior

- State format v2 stores flat offsets (legacy-compatible) plus `_files` metadata (`dev`, `ino`, `size`) and `version`.
- Rotation is detected by device/inode change, not size alone. Truncation (offset > current size) resets to zero. Metadata is refreshed after each successful persist, including restarted processes.
- Collection under monitoring uses `persist=False`; offsets are committed only by `commit_state()` after all batches are acknowledged.
- Corrupt state is quarantined as `.corrupt-<timestamp>` and collection restarts at zero (replay, never skip).
- Legacy flat checkpoints still load. Windows may lack stable inode values; the size fallback remains, with the documented rotation limitation.
- Crash between acknowledgement and checkpoint commit replays data; duplicates are preferred to loss.

## 8. Retry and backend recovery behavior

| Situation | Behavior |
|---|---|
| GET/HEAD 502/503/504, transport errors | Retried (existing conservative policy) |
| POST with `retry_transient=True` on 408/425/429/502/503/504 and transport/OS/timeout errors | Up to **3 attempts** |
| POST 500 | Not retried (ambiguous side effects); pending preserved |
| 401/403 | Not retried; authentication path |
| 422 and other 4xx | Not retried; batch preserved and error shown |
| Backoff | `min(0.5 * 2^attempt, 10s) * uniform(0.5, 1.0)` |
| `Retry-After` (seconds or HTTP date) | Honored, capped at 10 s |
| Cancellation | Stop cancels the sleep/request promptly; no further batches sent |

Recoverable failures leave the journal and checkpoint untouched. Pending data is retried on the next cycle and after restart. A full journal or storage error pauses collection with ERROR instead of discarding.

## 9. Authentication and session findings

- Login, token restoration, invalid credentials, expiry and logout were exercised by existing and new tests.
- A 401 during batch delivery now: records the failure, persists pending batches, clears the stored token/session, aborts the monitoring loop into a visible ERROR state, and leaves the backend session to be closed by `stop()`.
- Logout clears in-memory and persisted authentication material; no password is persisted, and token values never appear in errors or the report.
- Token/config/journal files are private (`0600`; parent dirs `0700`).
- No refresh mechanism or new authentication backend was added. Re-login is required after expiry, matching the server contract.
- TUI shows the authentication/error state instead of a false RUNNING state.

## 10. Monitoring lifecycle findings

- `STOPPED → STARTING → RUNNING → STOPPING → STOPPED`, plus `ERROR`, guarded by a lifecycle lock and a generation counter.
- Repeat start while RUNNING returns the existing service. Start after ERROR cancels and awaits any previous loop before resetting the stop event, preventing two polling loops.
- Stop during STARTING invalidates the generation; a session created by the losing start is stopped remotely rather than leaked.
- Stop during an in-flight request cancels within the stop timeout (default **10 s**) and closes the remote session within **5 s**.
- Delivery is serialized by a cycle lock, so force-cycle, the polling loop and stop cannot submit the same batch concurrently.
- On shutdown, the task and HTTP session are closed; a final task count of 1 (the runner) was observed after stop in the smoke test.
- `session_close` reports `closed` only after a successful backend stop; failures read `unknown (...)`; an uncreated session reads `unknown (session not created)`.
- Existing TUI status text was extended only; controls and shortcuts are unchanged.

## 11. Configuration and security findings

- Base URL must be `http://` or `https://`; intervals 10–86,400 s; max_results 1–20.
- Corrupt or unreadable config falls back to defaults and exposes `config_error`; startup no longer crashes silently.
- `configure_monitoring`/login are refused while monitoring is STARTING/RUNNING/STOPPING; changes after stop are validated and saved atomically.
- Config saves use temp file + `os.replace` + `0600`; failure is reported and the previous file is left intact.
- No secrets are logged; raw logs are not included in error messages or this report. No TLS bypass was introduced.
- Runtime auth, config, collector and queue files live outside Git; no new dependency was added.

## 12. Endurance test measurements

**PASS (short smoke only, not a long-running endurance test).**

- Duration: 30 s total, 5 s warm-up + **25.0 s measured**, one monitoring loop with a fast in-process fake transport (HTTP-shaped, no real network).
- Interval was clamped to the configured minimum of 10 s, so only **1 completed cycle** fell inside the measured window (2 HTTP calls total: session create + analyze).
- `VmRSS`: 34,796 KB → 34,796 KB (**0 KB delta**).
- Open file descriptors: 7 → 7.
- Asyncio tasks: 2 → 2 while running; **1** after stop.
- No background task, socket or table growth was observed in this window.

This is explicitly a smoke test; no multi-hour soak, real log-volume endurance run, or repeated login/logout stress was performed.

## 13. Real backend integration results

Real HTTP against the running local FastAPI + MongoDB (not mocked), using the existing development account; credentials were sourced from the local runtime file and never printed.

| Step | Result |
|---|---|
| `POST /login` | **200** |
| `GET /health` | **200**, services healthy |
| `POST /api/v1/monitoring/sessions` | **200**, session id returned |
| Harmless fixture: 90,064 chars in 2 lossless batches (49,972 + 40,092) | **200 + 200**; both responses contained summary/techniques; concatenated payload exactly 90,064 chars |
| Empty `logs` request | **500** (defect reconfirmed) |
| `POST /api/v1/monitoring/sessions/{id}/stop` | **200**, status `stopped` |
| Small AI-enhanced analyze (`enhance_with_ai=true`) | **200**, `enhanced_analysis` present |

This proves the former 50,000-character failure is resolved for real: the data was split, both halves were accepted, and no characters were discarded. The full automatic monitoring loop against live OS log files was exercised with mocks rather than the real TUI process; it was not driven end-to-end against live `/var/log` sources in this phase.

## 14. UI and theme regression results

- Full suite includes the existing layout and theme tests: **PASS**, unchanged.
- Six pages (Dashboard, Monitoring, Analysis, Knowledge, Sessions, Settings) open via shortcuts at **120×40** and **80×24** in headless Textual pilots; `app.view` switches correctly and the active theme remains registered.
- Theme files, palette, navigation, shortcuts, panel layout and CSS were not modified; theme switching tests still pass.
- Status additions are plain text in existing widgets: pending/submitted batches, delivery attempts, oversized batches, honest session-close text.
- **Not visually inspected**: no screenshot or live terminal rendering check was performed after the changes; verification was automated/headless.

## 15. Backend-owner issues (not modified)

| Issue | Status | Details / suggested correction |
|---|---|---|
| Hard-coded MongoDB TLS | **CONFIRMED** | `server/db.py` always passes `tlsCAFile=certifi.where()`. Local TLS Mongo works, but a non-TLS Mongo URL cannot be used. Suggest making TLS conditional on URL/`MONGO_TLS` setting. Severity: medium (deployment flexibility). |
| Empty `logs` returns 500 | **CONFIRMED** | Reproduced with an authenticated request. Pydantic accepts `""`; analysis path fails. Suggest `min_length=1` on `LogAnalysisRequest.logs` (422) or an explicit empty-input response. Severity: medium. |
| Missing `email-validator` | **RESOLVED locally** | Installed in `.venv-backend` and declared in `server/requirements.txt` (`email-validator==2.3.0`). |
| Missing knowledge framework data | **CONFIRMED** | `/health` reports `total_techniques: 0`, collection `okf-memory`. Analysis works but MITRE retrieval is empty. Suggest ingesting the ATT&CK/CVE bundle in the environment setup. Severity: high for knowledge features. |
| Unauthenticated knowledge endpoints | **CONFIRMED** | `server/routers/knowledge.py` has no `get_current_user` dependency; `GET /api/v1/knowledge/stats` returned **200 without a token**. Ingestion endpoints are likewise exposed. Suggest adding the existing bearer dependency. Severity: high (data ingestion/DoS surface). |
| Unavailable Gemini credentials | **NOT REPRODUCED** | A small AI-enhanced analyze returned 200 with `enhanced_analysis`, and `/health` reports Gemini healthy. Local credentials are working; no backend change needed. |

## 16. Final test results

- Complete CLI suite: **223 passed, 0 failed, 0 skipped** in 50.29 s.
- New focused areas: batching boundaries/oversize/order/no-loss; journal round-trip, permissions, capacity, corruption; multi-batch delivery, ack-gated checkpoint, restart replay, auth-expiry preservation, storage pause, session-close honesty, stop/start races, slow-request stop, concurrent force cycles; retry classification, Retry-After, bounds, cancellation; inode rotation, truncation, corrupt checkpoint, deferred commit, storage failure; config corruption/guard/atomicity.
- Existing functional, page, layout and theme tests all still pass.

## 17. Remaining risks

1. **Duplicate submissions** after ambiguous failures or crashes are possible by design (no backend idempotency).
2. An 8 MiB/64-batch journal can fill under a long outage with very high log volume; collection then pauses with ERROR rather than deleting data. Manual intervention/clearance may be required.
3. Windows lacks reliable inode metadata; rotation detection falls back to size and can miss same-size replacements.
4. HTTP 500 on analyze is not retried; a transient server-side 500 requires the next cycle.
5. No long-duration endurance or repeated login/logout soak was performed.
6. The TUI was verified headlessly, not visually, after these changes.
7. End-to-end live monitoring of real OS log files through the TUI was not run; live multi-batch submission was verified over real HTTP instead.
8. A pre-existing user runtime journal under `~/.config/forensiq/` was deliberately preserved; it was not replayed against the real backend during testing.
9. A crash between the final acknowledgement and checkpoint commit may replay a whole file, producing duplicate analyses.

## 18. Phase 8 recommendations

1. Add a backend idempotency key per batch and deduplicate inside the analyze endpoint, enabling safe automatic retries and moving toward effectively-once delivery.
2. Fix backend empty-log validation (422) and add authentication to all knowledge endpoints.
3. Make Mongo TLS configurable; document knowledge ingestion as part of environment setup.
4. Optionally aggregate multiple batch responses into one TUI analysis view instead of showing only the last batch's summary.
5. Add a genuine multi-hour soak test (memory, FDs, tasks, journal growth) and a real log-volume endurance run.
6. Consider a bounded retention/clear action for a permanently failed journal, with explicit user confirmation (never automatic deletion).

## 19. Exact reproducible launch commands

```bash
# From /home/pranav/Desktop/forensiq
bash cli_agent/scripts/dev_mongo.sh      # only if MongoDB is not already running
bash cli_agent/scripts/run_backend.sh    # only if the backend is not already healthy
bash cli_agent/scripts/run_tui.sh        # interactive TUI
```

Non-interactive verification:

```bash
cd /home/pranav/Desktop/forensiq
cli_agent/.venv/bin/python -m pytest cli_agent/tests -q
curl -sS http://127.0.0.1:8000/health
```

Runtime files (preserved, private): `~/.config/forensiq/{session.json,config.json,collector_state.json,pending_delivery.json}`.

**Status: Phase 7 complete. No commit was made. Waiting for user approval before Phase 8.**
