# ForensIQ CLI — Combined Phase 4 + 5 Report

Scope: convert the temporary Textual preview into the functional application
**without redesigning it**, apply an htop-inspired green palette, integrate
JWT authentication, configuration and automatic monitoring, rename the service
package, and correct the root `.gitignore` — all inside `cli_agent/` plus that
one approved root file.

Status: complete, stopped at the Phase 4 + 5 boundary. Nothing staged, committed
or pushed; no Phase 6 work started.

---

## 1. Deliverables

| # | Deliverable | Where |
|---|---|---|
| 1 | Existing TUI layout preserved | `cli_agent/tui/app.py` (compose tree identical to `preview.py`) |
| 2 | htop-inspired green palette | `cli_agent/tui/styles.tcss` (single stylesheet) |
| 3 | Functional authentication | `LoginScreen` + `services/auth_service.py` |
| 4 | Functional automatic monitoring | `services/monitoring_service.py`, wired from the TUI |
| 5 | Configuration integration | `services/config_service.py`, reflected in cards/panels/settings |
| 6 | Renamed service package | `cli_agent/client/` → `cli_agent/services/` |
| 7 | Corrected `.gitignore` | root `.gitignore` (anchored `/docs/`, `/client/`) |
| 8 | Passing automated tests | 132 passed, 0 failed |
| 9 | Launch command | `python -m cli_agent.tui` · `python -m cli_agent tui` |
| 10 | This report | `cli_agent/COMBINED_PHASE_4_5_REPORT.md` |

Files added in this phase:

```
cli_agent/tui/app.py                 functional Textual application
cli_agent/tui/styles.tcss            centralized palette (colours only)
cli_agent/tui/__main__.py            python -m cli_agent.tui
cli_agent/tests/test_tui_app.py      15 behavioural tests
cli_agent/tests/test_tui_layout.py   6 layout/palette regression tests
cli_agent/tests/test_services_package.py  7 rename + repo-hygiene tests
cli_agent/tests/test_collector_state.py   5 restart-safety tests
```

Files changed: `cli_agent/tui/__init__.py`, `cli_agent/cli.py`,
`cli_agent/__init__.py`, `cli_agent/legacy/__init__.py` (docstring only),
`cli_agent/pyproject.toml`, `cli_agent/services/*` (imports + two small
additions), `cli_agent/tests/*` (imports), root `.gitignore`.

---

## 2. Package rename: `client/` → `services/`

`git mv`-equivalent directory move plus a mechanical import rewrite; no module
was renamed internally and no behaviour changed.

* `cli_agent/services/` — `api_client.py`, `auth_service.py`, `cli_service.py`,
  `collector_service.py`, `config_service.py`, `errors.py`,
  `monitoring_service.py`, `response_adapter.py`, `__init__.py`.
* Updated references: `cli.py`, `cli_agent/__init__.py`,
  `cli_agent/legacy/__init__.py`, `tui/__init__.py`, `services/config_service.py`
  docstring, and every test module (including `conftest.py`).
* Verified: `cli_agent.client` no longer resolves, no source file imports it,
  and the old directory is gone (`tests/test_services_package.py`).

`pyproject.toml` gained an optional `tui` extra (`textual>=0.80`) so the
dashboard is not forced on CLI-only installs. Console scripts are unchanged:
`forensiq = cli_agent.cli:main`, `forensiq-legacy = cli_agent.legacy.cli_tool:main`.

---

## 3. Root `.gitignore` correction

Before: `docs/` and `client/` were unanchored, so they also matched
`cli_agent/docs/` and `cli_agent/client/` at any depth — `git check-ignore`
confirmed both. That silently hid part of `cli_agent/` from version control.

After:

```gitignore
.mcp.json
.freebuff
/docs/
/client/
server/frameworks/
LogIQ-main.zip
```

Verification (`git check-ignore -q`):

| path | result |
|---|---|
| `cli_agent/services/cli_service.py` | tracked |
| `cli_agent/docs/CLI_USER_GUIDE.md` | tracked |
| `cli_agent/tui/app.py` | tracked |
| `client/untracked_probe.py` | ignored |
| `docs/untracked_probe.md` | ignored |

`client/` already contains 47 tracked files in this repository, so git reports
the directory itself as not-ignored (tracked content is never ignored); the
anchored rule still protects every newly created file there. `cli_agent/` has
no ignore rule. Note: this file was modified twice during the phase — it was
reverted mid-session, and the approved correction was re-applied and re-tested.

---

## 4. Palette (colours only)

Centralized in `cli_agent/tui/styles.tcss`; `app.py` contains no `CSS` and no
`DEFAULT_CSS`.

| Element | Colour | Applied to |
|---|---|---|
| Main background | `#080C0A` | `Screen`, `#stream-panel`, `RichLog`, `Input` |
| Panel background | `#101713` | `Header`, `Footer`, `#sidebar`, `.card`, panels, `DataTable`, `Button` |
| Primary green | `#00C853` | `#brand`, `.panel-title` |
| Bright green | `#39FF88` | selected nav item, button focus/hover text, `.ok`, table header + cursor, running state |
| Muted green | `#4B8061` | every border, separator, `#brand-sub` |
| Selected item | `#176B3A` | `ListItem.--highlight`, table header/cursor, footer keys |
| Main text | `#E0E8E2` | `Screen`, `ListItem`, `DataTable`, `RichLog` |
| Secondary text | `#91A598` | `.kv`, `#view-note`, `Footer`, `.card-title` |
| Warning | `#E5B94B` | `.warn` (stopped/unauthenticated/stopping) |
| Error | `#F06464` | `.bad` (backend errors, failed login) |
| Information | `#5CC8D7` | `.info` (cycle submissions, session notices) |

No gradients, no glow, no new decorative effects. Amber and red are only used
for meaningful states; bright green marks active/selected/focused elements.

---

## 5. Layout preservation

`cli_agent/tui/preview.py` is left untouched as the frozen visual baseline.
`app.py` re-creates exactly its tree: `Header`, `#body` → (`#sidebar` with
`#brand`, `#brand-sub`, 6-item `ListView` | `#main` with `#view-note`, four
`.card`s, `#panels` → (`#monitor-panel` + `#controls` | `#technique-panel`), and
`#stream-panel`), then `Footer`. Same ids, same classes, same order; sizes
(`#sidebar` width 28, `#monitor-panel` width 44, `#stream-panel` height 12,
card height 5) are copied verbatim into the stylesheet.

Automated check: `test_widget_tree_is_identical_to_the_preview` renders the
preview in its own interpreter, records a structural fingerprint
(type, id, classes, containment, order, leaf-vs-container), renders the
functional app at the same 120×40 size and asserts equality. Companion checks:
all layout ids exist, there are exactly 4 cards and 6 nav items, the preview
shortcut set is a subset of the app's, the only added keys are `l` and `o`, and
no preview-era navy colour survives.

Content is live where the preview was mock: card values, monitor detail,
technique rows and the event stream now show real sessions, statistics,
analysis results and errors. That is data, not layout.

### Documented exceptions

1. **Sign-in modal** (`LoginScreen`, a Textual `ModalScreen`). Required because
   the backend issues JWTs through `POST /login` and the approved dashboard has
   no credential widgets. It is a separate overlay, styled from the same
   stylesheet; the dashboard composition is unchanged behind it.
2. **Two added bindings**: `l` (sign in) and `o` (sign out). Every pre-existing
   shortcut (`q`, `1`–`6`, `s`, `x`, `t`) keeps its key and meaning.
3. **Star-shaped text change**: the header subtitle reads
   "security operations console" instead of "preview build - mock data only",
   since the build is no longer a mock preview.

No other deviations: no htop tables, no CPU meters, no process lists, no new
panels or moved widgets.

---

## 6. Functional integration

### Authentication
* Session is restored on start from `~/.config/forensiq/session.json` (0600
  file, 0700 directory); an expired token is discarded locally.
* `l` opens the modal; `POST /login` is the existing backend route, the JWT is
  stored as before, and the password field is cleared after every attempt.
* Failures show the service's message (`incorrect username or password`) in the
  modal; the typed password is never echoed, logged or stored.
* `o` stops monitoring first, then discards the local token.
* No refresh flow is invented: a 401 still means "sign in again".
* The `AUTH` card shows the signed-in username or `signed out`.

### Configuration
* Loaded at startup from `~/.config/forensiq/config.json` via `ConfigService`.
* `BACKEND` card shows the configured host:port; the settings view
  (`6`) reports interval, max results, AI enhancement and sources from the live
  config object.
* Starting monitoring passes the configured interval, max results, enhancement
  flag and source list to the service; changes are persisted through the
  existing `ConfigService.update()` path.

### Monitoring
* `s` / **Start** calls `CliService.start_monitoring(...)` with the three
  service callbacks (`on_state_change`, `on_result`, `on_error`) — the existing
  client-owned polling loop, not a new engine.
* `x` / **Stop** awaits `stop_monitoring()` under a 15 s bound and reports
  timeout/failure instead of hanging.
* `t` / **Force cycle** calls the new `MonitoringService.force_cycle()`, which
  shares an `asyncio.Lock` with the scheduled loop, so a manual cycle can never
  overlap or double-submit a batch.
* Callbacks arrive on the app's event loop and are marshalled with
  `call_later`, so widget updates never race the loop task.
* Buttons reflect real state (`Start` disabled while running, `Stop` disabled
  while stopped); the monitoring card/detail show state, session id, adaptive
  interval, cycles, collected events, technique count and the last error.
* Backend failures are reported in the stream (`backend error: HTTP 500: ...`)
  and the loop keeps running; the service's existing retry/backoff policy is
  unchanged (POST is still never retried).

### Shutdown and cancellation
* `q`/Ctrl+C use Textual's own quit action; `on_unmount` then awaits
  `CliService.close()` (bounded to 15 s), which cancels the loop task, joins it
  and best-effort closes the backend session before the HTTP client closes.
* No `sys.exit`, no bare `while True`, no orphaned tasks; the shutdown tests
  assert the transport is closed and no monitoring service remains.
* `on_unmount` is async and the app deliberately does **not** override Textual's
  private `_shutdown` hook (doing so breaks framework teardown — found and
  fixed during this phase).

### Placeholders
* Analysis, Knowledge and Sessions remain placeholders: selecting them only
  updates the existing `#view-note` label, as in the preview.
* No manual log upload, no new backend endpoint, no HITL decision logic, and no
  change to any request/response contract (`/login`, `/register`, `/users/me`,
  `/api/v1/analyze`, `/api/v1/monitoring/sessions*`).

---

## 7. Collector restart safety

The legacy extractor keeps file read positions in `last_extraction_time` for
the lifetime of the process only. `CollectorService` now adds an opt-in,
service-level layer around it (legacy code untouched):

* persisted offsets at `~/.config/forensiq/collector_state.json`
  (`DEFAULT_COLLECTOR_STATE_PATH`, wired by `CliService`; disabled when
  `state_path=None`, which is what tests use);
* restore once on the first `collect()`, so a restart resumes instead of
  replaying the whole file;
* rotation/truncation guard: a stored offset larger than the current file size
  is reset to 0 and reported in `CollectorService.rotation_resets`;
* writes are atomic (`mkstemp` + `os.replace`) and best-effort — persistence can
  never break collection;
* unreadable/corrupt state files are ignored.

Not addressed (documented, unchanged legacy behaviour): no Windows event-log
record bookmarks, no inode tracking, per-source failures still surface as
"empty".

---

## 8. Tests

Command (from the repository root; `pytest.ini` lives in `cli_agent/`):

```bash
/tmp/forensiq_cli_venv/bin/python -m pytest cli_agent/tests -q
```

Result:

```
132 passed in 8.43s
```

Per file:

| File | Tests |
|---|---|
| `test_api_client.py` | 22 |
| `test_cli_regression.py` | 18 |
| `test_auth_service.py` | 15 |
| `test_tui_app.py` | 15 (new) |
| `test_response_adapter.py` | 13 |
| `test_monitoring.py` | 13 |
| `test_collector.py` | 11 |
| `test_services_package.py` | 7 (new) |
| `test_package.py` | 7 |
| `test_tui_layout.py` | 6 (new) |
| `test_collector_state.py` | 5 (new) |
| **Total** | **132** |

All Phase 2 + 3 tests still pass unchanged in intent; they only needed the
`cli_agent.client` → `cli_agent.services` import update.

Coverage added in this phase:

* **Authentication** — signed-out start blocks monitoring, restored session is
  shown, successful modal login dismisses and updates the card, failed login
  reports the error without leaking or retaining the password, logout stops
  monitoring and deletes the token file.
* **Configuration** — values loaded from disk reach the cards, the settings
  view and the monitoring interval actually passed to the service.
* **Monitoring lifecycle** — start runs a cycle and fills the existing widgets,
  stop closes the backend session, force-cycle submits an extra batch, force
  cycle before start only reports, start/stop button state tracks reality.
* **Backend failure handling** — a 503 on session registration and a 500 on
  analysis are reported in the stream while the loop survives.
* **Shutdown** — quitting with monitoring active stops it and closes the
  transport; quitting without monitoring is clean and leaves no tasks.
* **Navigation/keyboard** — `1`–`6` still switch views; the preview's shortcut
  set is a subset of the app's, with only `l`/`o` added.
* **Visual regression** — structural fingerprint equality against the live
  preview plus palette assertions.
* **Rename/hygiene** — `cli_agent.services` surface, absence of
  `cli_agent.client`, console scripts, `tui` subcommand, gitignore behaviour.
* **Restart safety** — offsets persist/resume, corrupt state ignored, rotation
  resets a stale offset, persistence stays opt-in.

Additional checks run:

```
python -m compileall -q cli_agent                     -> exit 0
python -m cli_agent --help                            -> lists tui, exit 0
python -m cli_agent --version                         -> forensiq 0.1.0
git check-ignore -q <paths>                           -> see section 3
```

---

## 9. Launch

```bash
cd /home/pranav/Desktop/forensiq
/tmp/forensiq_cli_venv/bin/python -m cli_agent.tui
```

Equivalent, once the package is installed (`pip install -e './cli_agent[tui]'`):

```bash
forensiq tui
```

Keys: `q` quit · `1`–`6` views · `s` start · `x` stop · `t` force cycle ·
`l` sign in · `o` sign out.

If `textual` is missing, `forensiq tui` exits with a one-line hint instead of a
traceback.

---

## 10. Limitations and not-verified items

* No live backend was available during this phase: authentication, analysis and
  session endpoints were exercised through the injectable fake transport, not
  against a running server. End-to-end verification against
  `http://localhost:8000` is still outstanding.
* The visual regression is structural (widget tree + palette), not a pixel
  diff: no screenshot comparison was performed. Appearance at narrow widths
  (the earlier ~60-column panel) can still truncate card text, as in the
  preview.
* Analysis, Knowledge and Sessions screens intentionally remain placeholders.
* The collector still has the legacy limitations listed in section 7.
* `textual` is an optional extra; the CLI works without it.
* The backend test suite was not run (out of scope; it previously failed
  collection on a missing `langchain_core`).
* Nothing was staged, committed or pushed, and no Git history was rewritten.

## 11. Open items

1. Confirm that `monitor --schedule` stays unsupported (carried over from the
   Phase 2 + 3 report).
2. The archive sample `cli_agent/test_logs/sample_security.log` referenced by
   `server/services/knowledge/demo_logs_kcp.py:146` is still absent (carried
   over; server-side path, not added here).
3. Rotate the PyPI/TestPyPI tokens found in the original archive's
   `aiagent/.env.example` and `aiagent/.pypirc` (reported earlier, not copied).
