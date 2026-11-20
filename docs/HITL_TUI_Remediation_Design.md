# ForensIQ — Human-in-the-Loop (HITL) TUI Remediation & System Fix Design

## 1. Purpose & Core Philosophy

**Core Principle:** *"Let AI investigate. Never let it self-authorize."*

ForensIQ's LangGraph multi-agent system already produces structured, evidence-linked remediation proposals (`RecommendationItem` in `server/services/investigation/models.py`) with hard safety invariants:
- `requires_human_approval: Literal[True] = True`
- `auto_executable: Literal[False] = False`
- Mandatory `target`, `action`, `expected_effect`, `evidence_event_ids`, and `rollback_notes`.

However, an analyst triaging an incident in the local terminal (`cli_agent/tui`) still needs a fast, safe way to **act** on fixable issues without manually writing shell commands under pressure or risking broken configurations.

The **HITL TUI Remediation Engine** bridges this gap using a **"Server Proposes, Local TUI Disposes"** architecture:
1. The **Backend** never executes host commands and never receives root/sudo credentials. It emits structured, parameterized remediation proposals tied to verified log evidence.
2. The **Local Textual TUI (`cli_agent/tui`)** maps fixable recommendations to a **strict local playbook registry**, performs pre-flight checks on the host, previews exact commands or config diffs, requires explicit human approval, logs a local rollback journal, and provides one-key undo/rollback.

---

## 2. End-to-End Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ForensIQ Backend (FastAPI + LangGraph Multi-Agent Orchestrator)              │
│                                                                              │
│  Log Evidence + OKF (MITRE/CVE) + LSTM SequenceCue                           │
│        │                                                                     │
│        ▼                                                                     │
│  Recommendation Sub-Agent + Deterministic Verifier                           │
│  Emits RecommendationItem (requires_human_approval=True, auto_executable=False)
│  + structured playbook_id & validated playbook_params                        │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ HTTPS / JSON (InvestigationResult)
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ Local Host — ForensIQ Textual TUI (cli_agent/tui)                            │
│                                                                              │
│  1. Playbook Resolver & Strict Parameter Validator (Anti-Prompt-Injection)   │
│  2. Pre-Flight / Dry-Run Inspector (checks user, IP, PID, file, package)     │
│  3. Interactive HITL Review Pane (Command / Diff Preview + Rollback Plan)    │
│  4. Human Approval Gate ([A] Approve  [D] Dry-Run  [R] Reject  [U] Undo)     │
│  5. Local Execution Engine + Backup (.forensiq.bak) + Rollback Journal       │
│  6. Optional Status Sync -> Backend Audit Trail                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Three Tiers of Fixability & Safety Guardrails

To prevent arbitrary LLM-generated shell execution (which could be hijacked via prompt injection inside untrusted log lines), all remediations are classified into three deterministic tiers:

| Tier | Classification | Examples | TUI Execution Model |
| :--- | :--- | :--- | :--- |
| **Tier 1** | **Deterministic Playbooks (Auto-Fixable with Approval)** | • Block attacker IP (`ufw` / `nftables` / `iptables`)<br>• Lock compromised local account (`usermod -L <user>`)<br>• Terminate malicious session/PID (`pkill -KILL -u <user>` / `kill -9 <pid>`)<br>• Restore sensitive file permissions (`chmod 600 /etc/shadow`)<br>• Disable rogue systemd service (`systemctl disable --now <svc>`) | **1-Key Approve & Execute** after pre-flight validation + **1-Key Rollback** using recorded pre-change state. |
| **Tier 2** | **Guided Config & Patch Fixes (Diff + Validation + Approval)** | • Harden `/etc/ssh/sshd_config` (`PermitRootLogin no`, `PasswordAuthentication no`)<br>• Patch vulnerable package matched to a CVE (`apt` / `pacman` / `dnf`)<br>• Quarantine or remove unauthorized cron job in `/etc/cron.d/` | Shows **Before/After Unified Diff**, snapshots original file to `~/.forensiq/backups/`, runs config syntax validator (e.g., `sshd -t`), and applies only on confirmation. |
| **Tier 3** | **Manual / Advisory Runbooks (Not Locally Executable)** | • Rotate external cloud IAM keys or enforce IdP-wide MFA<br>• Isolate upstream switch port or capture full disk forensic image | Displayed as **`[ADVISORY_ONLY]`** with an interactive analyst checklist; cannot be executed as a shell command. |

### Prompt-Injection Immunity
The TUI **never** passes free-text `RecommendationItem.action` to `sh -c`. Instead:
- The TUI maintains a local Python registry of parameterized playbooks (`PLAYBOOK_REGISTRY`).
- Every parameter in `playbook_params` is validated against strict regex/type schemas before command construction (`ipaddress.ip_address(ip)`, `^[a-z_][a-z0-9_-]{0,31}$` for usernames, integer PIDs, allowlisted config keys).
- Commands are executed via `subprocess.run([...], shell=False)` argument lists.

---

## 4. Contract & Schema Extension

Extend `RecommendationItem` in `server/services/investigation/models.py` with backward-compatible optional fields (all existing tests and frontend components continue working without change):

```python
PlaybookId = Literal[
    "block_ip",
    "lock_user",
    "terminate_user_sessions",
    "kill_process",
    "fix_file_permissions",
    "harden_sshd_config",
    "quarantine_cron_file",
    "upgrade_package",
    "manual_only",
]

RemediationStatus = Literal[
    "pending_approval",
    "approved",
    "executed",
    "failed",
    "rejected",
    "rolled_back",
]


class RecommendationItem(BaseModel):
    recommendation_id: str
    priority: Literal["immediate", "short_term", "long_term"]
    title: str
    target: str
    action: str
    expected_effect: str
    supporting_finding_ids: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    knowledge_mitigation_ids: list[str] = Field(default_factory=list)
    requires_human_approval: Literal[True] = True
    auto_executable: Literal[False] = False
    rollback_notes: str = Field(default="")

    # HITL TUI Remediation extensions (backward-compatible defaults)
    fixable_via_tui: bool = Field(
        default=False,
        description="True when a deterministic Tier-1 or Tier-2 local TUI playbook applies",
    )
    fix_tier: Literal["tier_1_playbook", "tier_2_config_diff", "tier_3_advisory"] = Field(
        default="tier_3_advisory"
    )
    playbook_id: PlaybookId = Field(default="manual_only")
    playbook_params: dict[str, str] = Field(
        default_factory=dict,
        description="Validated key-value parameters for the local TUI playbook",
    )
    execution_status: RemediationStatus = Field(default="pending_approval")
```

---

## 5. Local Playbook Registry Specification (`cli_agent/remediation/`)

Each playbook in the TUI implements a uniform interface:

```python
class RemediationPlaybook(Protocol):
    playbook_id: str
    tier: Literal["tier_1_playbook", "tier_2_config_diff"]

    def validate_params(self, params: Mapping[str, str]) -> dict[str, str]:
        """Validate and sanitize parameters (raises ValueError on invalid/unsafe input)."""

    def preflight_check(self, params: Mapping[str, str]) -> PreflightReport:
        """Read-only check confirming target exists on host and whether fix is already applied."""

    def render_preview(self, params: Mapping[str, str]) -> CommandOrDiffPreview:
        """Return exact argv list(s) or unified file diff plus rollback argv list(s)."""

    def execute(self, params: Mapping[str, str], journal: RollbackJournal) -> ExecutionReceipt:
        """Execute fix with shell=False, store backup/undo record in journal, return receipt."""

    def rollback(self, receipt: ExecutionReceipt) -> RollbackReceipt:
        """Revert the fix using the recorded rollback command or backup file."""
```

### Initial Built-In Playbooks
1. **`lock_user`** (`params: {"username": "..."}`)
   - *Guardrail:* Refuses `root` or current logged-in analyst user (`os.getlogin()` / `UID 0`).
   - *Pre-flight:* Checks `pwd.getpwnam(username)` and `passwd -S <username>`.
   - *Command:* `["sudo", "-n", "usermod", "-L", username]` (or prompts for sudo password in TUI modal).
   - *Rollback:* `["sudo", "-n", "usermod", "-U", username]`.
2. **`terminate_user_sessions`** (`params: {"username": "..."}`)
   - *Guardrail:* Refuses `root` or current TUI user.
   - *Pre-flight:* Lists active sessions via `who` / `pgrep -u <username>`.
   - *Command:* `["sudo", "-n", "pkill", "-KILL", "-u", username]`.
   - *Rollback:* Advisory note (terminated processes are logged in the journal with their prior PIDs/cmdlines).
3. **`block_ip`** (`params: {"ip": "..."}`)
   - *Guardrail:* Parses via `ipaddress.ip_address(ip)`; refuses loopback (`127.0.0.0/8`, `::1`), link-local, or the ForensIQ backend server IP.
   - *Pre-flight:* Detects active firewall (`ufw`, `nft`, or `iptables`) and checks if rule already exists.
   - *Command:* e.g. `["sudo", "-n", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]`.
   - *Rollback:* `["sudo", "-n", "ufw", "delete", "deny", "from", ip, "to", "any"]`.
4. **`fix_file_permissions`** (`params: {"path": "...", "mode": "0600"}`)
   - *Guardrail:* Allowlisted critical paths (`/etc/shadow`, `/etc/gshadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`).
   - *Pre-flight:* Reads current mode via `os.stat(path).st_mode`.
   - *Command:* `["sudo", "-n", "chmod", mode, path]`.
   - *Rollback:* Restores original octal mode recorded during pre-flight.
5. **`harden_sshd_config`** (`params: {"directive": "PermitRootLogin", "value": "no"}`)
   - *Guardrail:* Allowlisted directives (`PermitRootLogin`, `PasswordAuthentication`, `MaxAuthTries`).
   - *Pre-flight & Preview:* Generates a unified diff of `/etc/ssh/sshd_config`.
   - *Execute:* Copies `/etc/ssh/sshd_config` to `~/.forensiq/backups/sshd_config.<ts>.bak`, writes updated config, runs `sudo sshd -t` to verify syntax (auto-restores backup if `sshd -t` fails!), and reloads `sshd`.
   - *Rollback:* Restores backup file and reloads `sshd`.

---

## 6. Textual TUI User Experience (`cli_agent/tui`)

### 6.1 Sidebar Navigation Addition
Add **`("remediation", "Remediation", "HITL system fixes & rollback")`** to `NAV_ITEMS` in `cli_agent/tui/`, with a live badge counter showing pending fixable recommendations.

### 6.2 Layout of the `Remediation` Screen
```text
┌─ [HITL_REMEDIATION_QUEUE] ── Investigation: inv-94a1f ── Host: prod-web-01 ──────────┐
│Queue: 2 Fixable (Tier 1/2) · 1 Advisory (Tier 3) · 0 Executed                        │
├───────────────────────────────────┬──────────────────────────────────────────────────┤
│ RECOMMENDATIONS                   │ SELECTED FIX PREVIEW: [rec-001]                  │
│                                   │                                                  │
│ > [rec-001] Lock user 'deploy'    │ TITLE     : Lock Compromised Account 'deploy'    │
│   IMMEDIATE · Tier 1 · PENDING    │ FINDING   : find-001 (SSH Brute Force -> Sudo)   │
│                                   │ EVIDENCE  : evt-batch-49c7-0001, evt-49c7-0002   │
│   [rec-002] Block IP 203.0.113.45 │ MITIGATION: M1032 / Account Access Removal       │
│   IMMEDIATE · Tier 1 · PENDING    │                                                  │
│                                   │ PRE-FLIGHT: [PASS] User 'deploy' exists (1002)   │
│   [rec-003] Enforce MFA on SSH    │ COMMAND   : sudo usermod -L deploy               │
│   SHORT_TERM · Tier 3 · ADVISORY  │ EFFECT    : Blocks password/PAM logins for deploy│
│                                   │ ROLLBACK  : sudo usermod -U deploy               │
│                                   │                                                  │
│                                   │ [A] Approve & Fix  [D] Dry-Run  [R] Reject       │
├───────────────────────────────────┴──────────────────────────────────────────────────┤
│ LOCAL ROLLBACK JOURNAL (~/.forensiq/remediation_journal.json)            [U] Undo    │
│ • No fixes executed in current session.                                              │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Keybindings & Modals
- **`d` / `[D] Dry-Run`:** Runs `preflight_check()` and displays whether the target exists, current state, and whether `sudo` elevation is required.
- **`a` / `[A] Approve & Fix`:** Opens a confirmation modal displaying the exact command/diff and rollback command. If `sudo` requires a password, collects it via a masked Textual `Input(password=True)` widget in memory only.
- **`r` / `[R] Reject`:** Marks the recommendation as `rejected` (with optional analyst note) so it is excluded from active queue counts.
- **`u` / `[U] Undo / Rollback`:** Reverts the selected journal entry using its recorded rollback command or file backup.

---

## 7. Local Rollback Journal & Backend Audit Sync

### 7.1 Local Journal (`~/.forensiq/remediation_journal.json`)
Every approved execution appends an immutable receipt locally on the host:
```json
{
  "receipt_id": "fix-20261120-001",
  "investigation_id": "inv-94a1f",
  "recommendation_id": "rec-001",
  "playbook_id": "lock_user",
  "playbook_params": {"username": "deploy"},
  "executed_at_utc": "2026-11-20T01:45:00Z",
  "executed_by": "vaibhi",
  "command_argv": ["sudo", "-n", "usermod", "-L", "deploy"],
  "rollback_argv": ["sudo", "-n", "usermod", "-U", "deploy"],
  "backup_path": null,
  "exit_code": 0,
  "status": "executed"
}
```

### 7.2 Optional Backend Audit Endpoint
- **`POST /api/v1/investigations/{investigation_id}/remediation-status`** (or `/api/v1/history/{analysis_id}/remediation-status`)
- Allows the TUI to report `{"recommendation_id": "rec-001", "execution_status": "executed", "receipt_id": "fix-20261120-001", "notes": "..."}` back to the server so the web UI (`DASHBOARD.SYS` and `INVESTIGATION_INTEL` → `RECOMMENDATIONS`) reflects that the fix was approved and applied via TUI.

---

## 8. Phased Implementation Plan (Once Initial TUI Lands)

1. **Phase 1 — Contract & Backend Tagging:**
   - Add `fixable_via_tui`, `fix_tier`, `playbook_id`, `playbook_params`, and `execution_status` to `RecommendationItem` in `server/services/investigation/models.py`.
   - Add a deterministic post-processor in `recommendation_agent.py` that maps common findings/IOCs (e.g., external attacker IP from `authentication_failure`, compromised account from `privilege_escalation`, `/etc/shadow` access) to `block_ip`, `lock_user`, `harden_sshd_config`, or `fix_file_permissions`.
2. **Phase 2 — Local Playbook Engine & Rollback Journal (`cli_agent/remediation/`):**
   - Implement `playbook_registry.py`, parameter validators, pre-flight checkers, and `RollbackJournal` with unit tests using mocked `subprocess.run`.
3. **Phase 3 — Textual TUI Integration (`cli_agent/tui/`):**
   - Add the `Remediation` view, command/diff preview pane, confirmation modal, and one-key rollback binding (`a`, `d`, `r`, `u`).

