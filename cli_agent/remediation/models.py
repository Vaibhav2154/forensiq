"""Data models for the ForensIQ local HITL remediation engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Mapping


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

FixTier = Literal["tier_1_playbook", "tier_2_config_diff", "tier_3_advisory"]

RemediationStatus = Literal[
    "pending_approval",
    "approved",
    "executed",
    "failed",
    "rejected",
    "rolled_back",
]


@dataclass
class RemediationItemView:
    """Normalized recommendation view rendered in the TUI Remediation queue."""

    recommendation_id: str
    title: str
    priority: str
    target: str
    action: str
    expected_effect: str = ""
    supporting_finding_ids: tuple[str, ...] = ()
    evidence_event_ids: tuple[str, ...] = ()
    knowledge_mitigation_ids: tuple[str, ...] = ()
    rollback_notes: str = ""
    fixable_via_tui: bool = False
    fix_tier: FixTier = "tier_3_advisory"
    playbook_id: PlaybookId = "manual_only"
    playbook_params: dict[str, str] = field(default_factory=dict)
    execution_status: RemediationStatus = "pending_approval"
    requires_human_approval: bool = True
    auto_executable: bool = False
    analyst_note: str = ""

    @property
    def tier_label(self) -> str:
        return {
            "tier_1_playbook": "Tier 1",
            "tier_2_config_diff": "Tier 2",
            "tier_3_advisory": "Tier 3",
        }.get(self.fix_tier, "Tier 3")

    @property
    def is_executable_locally(self) -> bool:
        return (
            self.fixable_via_tui
            and self.fix_tier in ("tier_1_playbook", "tier_2_config_diff")
            and self.playbook_id != "manual_only"
        )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], index: int = 1) -> "RemediationItemView":
        rec_id = str(raw.get("recommendation_id") or f"rec-{index:03d}")
        tier = str(raw.get("fix_tier") or "tier_3_advisory")
        if tier not in ("tier_1_playbook", "tier_2_config_diff", "tier_3_advisory"):
            tier = "tier_3_advisory"
        playbook = str(raw.get("playbook_id") or "manual_only")
        valid_playbooks = {
            "block_ip",
            "lock_user",
            "terminate_user_sessions",
            "kill_process",
            "fix_file_permissions",
            "harden_sshd_config",
            "quarantine_cron_file",
            "upgrade_package",
            "manual_only",
        }
        if playbook not in valid_playbooks:
            playbook = "manual_only"
        status = str(raw.get("execution_status") or "pending_approval")
        if status not in (
            "pending_approval",
            "approved",
            "executed",
            "failed",
            "rejected",
            "rolled_back",
        ):
            status = "pending_approval"
        raw_params = raw.get("playbook_params")
        params = (
            {str(k): str(v) for k, v in raw_params.items()}
            if isinstance(raw_params, Mapping)
            else {}
        )
        fixable = bool(raw.get("fixable_via_tui", False)) and playbook != "manual_only"
        if not fixable:
            tier = "tier_3_advisory"
            playbook = "manual_only"
            params = {}
        return cls(
            recommendation_id=rec_id,
            title=str(raw.get("title") or rec_id),
            priority=str(raw.get("priority") or "short_term"),
            target=str(raw.get("target") or "host"),
            action=str(raw.get("action") or ""),
            expected_effect=str(raw.get("expected_effect") or ""),
            supporting_finding_ids=tuple(str(x) for x in (raw.get("supporting_finding_ids") or [])),
            evidence_event_ids=tuple(str(x) for x in (raw.get("evidence_event_ids") or [])),
            knowledge_mitigation_ids=tuple(
                str(x) for x in (raw.get("knowledge_mitigation_ids") or [])
            ),
            rollback_notes=str(raw.get("rollback_notes") or ""),
            fixable_via_tui=fixable,
            fix_tier=tier,  # type: ignore[arg-type]
            playbook_id=playbook,  # type: ignore[arg-type]
            playbook_params=params,
            execution_status=status,  # type: ignore[arg-type]
            requires_human_approval=True,
            auto_executable=False,
        )


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one local ``subprocess.run(argv, shell=False)`` invocation."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class PreflightReport:
    """Read-only host inspection result before human approval."""

    passed: bool
    summary: str
    already_applied: bool = False
    requires_sudo: bool = True
    details: tuple[str, ...] = ()
    observed_state: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CommandOrDiffPreview:
    """Exact argv command(s) or unified file diff shown to the analyst before approval."""

    command_argv: tuple[str, ...] = ()
    rollback_argv: tuple[str, ...] = ()
    unified_diff: str | None = None
    target_path: str | None = None
    summary: str = ""


@dataclass
class ExecutionReceipt:
    """Immutable-style receipt appended to ``~/.forensiq/remediation_journal.json``."""

    receipt_id: str
    investigation_id: str
    recommendation_id: str
    playbook_id: str
    playbook_params: dict[str, str]
    executed_at_utc: str
    executed_by: str
    command_argv: list[str]
    rollback_argv: list[str]
    backup_path: str | None = None
    exit_code: int = 0
    status: RemediationStatus = "executed"
    stdout: str = ""
    stderr: str = ""
    analysis_id: str | None = None
    rollback_notes: str = ""
    rolled_back_at_utc: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ExecutionReceipt":
        return cls(
            receipt_id=str(raw.get("receipt_id") or ""),
            investigation_id=str(raw.get("investigation_id") or ""),
            recommendation_id=str(raw.get("recommendation_id") or ""),
            playbook_id=str(raw.get("playbook_id") or "manual_only"),
            playbook_params={
                str(k): str(v) for k, v in (raw.get("playbook_params") or {}).items()
            },
            executed_at_utc=str(raw.get("executed_at_utc") or ""),
            executed_by=str(raw.get("executed_by") or ""),
            command_argv=[str(x) for x in (raw.get("command_argv") or [])],
            rollback_argv=[str(x) for x in (raw.get("rollback_argv") or [])],
            backup_path=str(raw["backup_path"]) if raw.get("backup_path") else None,
            exit_code=int(raw.get("exit_code", 0)),
            status=str(raw.get("status") or "executed"),  # type: ignore[arg-type]
            stdout=str(raw.get("stdout") or ""),
            stderr=str(raw.get("stderr") or ""),
            analysis_id=str(raw["analysis_id"]) if raw.get("analysis_id") else None,
            rollback_notes=str(raw.get("rollback_notes") or ""),
            rolled_back_at_utc=(
                str(raw["rolled_back_at_utc"]) if raw.get("rolled_back_at_utc") else None
            ),
        )


@dataclass(frozen=True)
class RollbackReceipt:
    """Result of reverting an executed remediation receipt."""

    receipt_id: str
    rolled_back_at_utc: str
    rollback_argv: tuple[str, ...]
    backup_restored: str | None = None
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    success: bool = True
    message: str = ""
