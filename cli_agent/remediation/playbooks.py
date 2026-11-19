"""Strict parameterized local remediation playbooks (shell=False, rollback-capable)."""

from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Mapping, Protocol, Sequence

from .journal import RollbackJournal
from .models import (
    CommandOrDiffPreview,
    CommandResult,
    ExecutionReceipt,
    PreflightReport,
    RollbackReceipt,
)
from .validators import (
    current_login_username,
    validate_cron_file_path,
    validate_file_permission_params,
    validate_ip,
    validate_package_name,
    validate_pid,
    validate_sshd_params,
    validate_username,
)


CommandRunner = Callable[[Sequence[str], str | None], CommandResult]


def default_command_runner(
    argv: Sequence[str],
    sudo_password: str | None = None,
) -> CommandResult:
    """Execute ``argv`` strictly with ``shell=False``.

    If ``sudo_password`` is supplied in memory for a ``sudo -n ...`` command,
    switches to ``sudo -S -p ""`` and pipes the password via stdin without ever
    logging or recording the secret.
    """
    exec_argv = list(argv)
    stdin_text: str | None = None
    if sudo_password is not None and exec_argv and exec_argv[0] == "sudo":
        if len(exec_argv) > 1 and exec_argv[1] == "-n":
            exec_argv = ["sudo", "-S", "-p", "", *exec_argv[2:]]
        else:
            exec_argv = ["sudo", "-S", "-p", "", *exec_argv[1:]]
        stdin_text = f"{sudo_password}\n"

    try:
        completed = subprocess.run(
            exec_argv,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            check=False,
        )
        return CommandResult(
            argv=tuple(argv),  # Never store password-transformed argv
            exit_code=int(completed.returncode),
            stdout=(completed.stdout or "").strip(),
            stderr=(completed.stderr or "").strip(),
        )
    except FileNotFoundError as exc:
        return CommandResult(
            argv=tuple(argv),
            exit_code=127,
            stderr=f"command not found: {exc.filename or exec_argv[0]}",
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            argv=tuple(argv),
            exit_code=124,
            stderr="command timed out after 30s",
        )
    except OSError as exc:
        return CommandResult(
            argv=tuple(argv),
            exit_code=1,
            stderr=str(exc),
        )


@dataclass
class HostContext:
    """Injectable host environment hooks so all playbooks are 100% testable offline."""

    runner: CommandRunner = default_command_runner
    which: Callable[[str], str | None] = shutil.which
    blocked_ips: tuple[str, ...] = ()
    current_user: str | None = None
    sshd_config_path: Path = Path("/etc/ssh/sshd_config")
    read_file: Callable[[Path], str] | None = None
    stat_mode: Callable[[Path], int | None] | None = None
    user_lookup: Callable[[str], tuple[int, str] | None] | None = None

    def active_username(self) -> str:
        return self.current_user if self.current_user is not None else current_login_username()

    def lookup_user(self, username: str) -> tuple[int, str] | None:
        if self.user_lookup is not None:
            return self.user_lookup(username)
        try:
            import pwd  # Unix only

            entry = pwd.getpwnam(username)
            return entry.pw_uid, entry.pw_shell
        except (ImportError, KeyError):
            return None

    def get_file_mode(self, path: Path) -> int | None:
        if self.stat_mode is not None:
            return self.stat_mode(path)
        try:
            return stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            return None

    def read_text(self, path: Path) -> str | None:
        if self.read_file is not None:
            try:
                return self.read_file(path)
            except OSError:
                return None
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None


class RemediationPlaybook(Protocol):
    playbook_id: str
    tier: Literal["tier_1_playbook", "tier_2_config_diff"]

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]: ...
    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport: ...
    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview: ...
    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt: ...
    def rollback(
        self,
        receipt: ExecutionReceipt,
        ctx: HostContext,
        *,
        sudo_password: str | None = None,
    ) -> RollbackReceipt: ...


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_receipt(
    *,
    journal: RollbackJournal,
    investigation_id: str,
    recommendation_id: str,
    analysis_id: str | None,
    playbook_id: str,
    params: dict[str, str],
    ctx: HostContext,
    command_argv: Sequence[str],
    rollback_argv: Sequence[str],
    result: CommandResult,
    backup_path: str | None = None,
    rollback_notes: str = "",
) -> ExecutionReceipt:
    return ExecutionReceipt(
        receipt_id=journal.next_receipt_id(),
        investigation_id=investigation_id,
        analysis_id=analysis_id,
        recommendation_id=recommendation_id,
        playbook_id=playbook_id,
        playbook_params=dict(params),
        executed_at_utc=_utc_iso(),
        executed_by=ctx.active_username(),
        command_argv=list(command_argv),
        rollback_argv=list(rollback_argv),
        backup_path=backup_path,
        exit_code=result.exit_code,
        status="executed" if result.exit_code == 0 else "failed",
        stdout=result.stdout,
        stderr=result.stderr,
        rollback_notes=rollback_notes,
    )


def _standard_rollback(
    receipt: ExecutionReceipt,
    ctx: HostContext,
    *,
    sudo_password: str | None = None,
) -> RollbackReceipt:
    if not receipt.rollback_argv:
        return RollbackReceipt(
            receipt_id=receipt.receipt_id,
            rolled_back_at_utc=_utc_iso(),
            rollback_argv=(),
            exit_code=1,
            success=False,
            message=receipt.rollback_notes or "No automated rollback command recorded for this receipt.",
        )
    res = ctx.runner(receipt.rollback_argv, sudo_password)
    return RollbackReceipt(
        receipt_id=receipt.receipt_id,
        rolled_back_at_utc=_utc_iso(),
        rollback_argv=tuple(receipt.rollback_argv),
        backup_restored=receipt.backup_path,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
        success=res.exit_code == 0,
        message="Rollback command executed successfully." if res.exit_code == 0 else (res.stderr or "Rollback failed."),
    )


# ---------------------------------------------------------------------------
# Tier 1 Playbooks
# ---------------------------------------------------------------------------


class LockUserPlaybook:
    playbook_id = "lock_user"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_1_playbook"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        username = validate_username(params.get("username", ""), current_user=ctx.active_username())
        return {"username": username}

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        user = clean["username"]
        info = ctx.lookup_user(user)
        if info is None:
            return PreflightReport(
                passed=False,
                summary=f"[FAIL] Local account {user!r} not found on this host.",
                requires_sudo=True,
                details=("Account lookup via passwd returned no entry.",),
            )
        uid, shell = info
        if uid == 0:
            return PreflightReport(
                passed=False,
                summary=f"[FAIL] Refusing to lock UID 0 account {user!r}.",
                requires_sudo=True,
            )
        status_res = ctx.runner(["passwd", "-S", user], None)
        already_locked = status_res.exit_code == 0 and " L " in f" {status_res.stdout} "
        return PreflightReport(
            passed=True,
            already_applied=already_locked,
            requires_sudo=True,
            summary=(
                f"[PASS] User {user!r} exists (uid={uid}, shell={shell})"
                + (" — already locked" if already_locked else "")
            ),
            details=(status_res.stdout or "passwd -S check completed",),
            observed_state={"uid": str(uid), "shell": shell},
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        user = clean["username"]
        return CommandOrDiffPreview(
            command_argv=("sudo", "-n", "usermod", "-L", user),
            rollback_argv=("sudo", "-n", "usermod", "-U", user),
            summary=f"Lock local password/PAM authentication for user {user!r}",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        preview = self.render_preview(clean, ctx)
        result = ctx.runner(preview.command_argv, sudo_password)
        receipt = _build_receipt(
            journal=journal,
            investigation_id=investigation_id,
            recommendation_id=recommendation_id,
            analysis_id=analysis_id,
            playbook_id=self.playbook_id,
            params=clean,
            ctx=ctx,
            command_argv=preview.command_argv,
            rollback_argv=preview.rollback_argv,
            result=result,
        )
        return journal.append(receipt)

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return _standard_rollback(receipt, ctx, sudo_password=sudo_password)


class TerminateUserSessionsPlaybook:
    playbook_id = "terminate_user_sessions"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_1_playbook"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        username = validate_username(params.get("username", ""), current_user=ctx.active_username())
        return {"username": username}

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        user = clean["username"]
        pgrep_res = ctx.runner(["pgrep", "-a", "-u", user], None)
        procs = [line for line in pgrep_res.stdout.splitlines() if line.strip()]
        if not procs:
            return PreflightReport(
                passed=True,
                already_applied=True,
                requires_sudo=True,
                summary=f"[PASS] No active processes currently running for {user!r}.",
                details=("Nothing to terminate.",),
            )
        return PreflightReport(
            passed=True,
            already_applied=False,
            requires_sudo=True,
            summary=f"[PASS] Found {len(procs)} active process(es) for {user!r}.",
            details=tuple(procs[:8]),
            observed_state={"active_pids": ", ".join(p.split()[0] for p in procs[:8])},
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        user = clean["username"]
        return CommandOrDiffPreview(
            command_argv=("sudo", "-n", "pkill", "-KILL", "-u", user),
            rollback_argv=(),
            summary=f"Terminate all active sessions/processes for user {user!r}",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        preflight = self.preflight_check(clean, ctx)
        preview = self.render_preview(clean, ctx)
        result = ctx.runner(preview.command_argv, sudo_password)
        prior_pids = preflight.observed_state.get("active_pids", "none")
        receipt = _build_receipt(
            journal=journal,
            investigation_id=investigation_id,
            recommendation_id=recommendation_id,
            analysis_id=analysis_id,
            playbook_id=self.playbook_id,
            params=clean,
            ctx=ctx,
            command_argv=preview.command_argv,
            rollback_argv=(),
            result=result,
            rollback_notes=f"Process termination is non-reversible; prior PIDs recorded: {prior_pids}",
        )
        return journal.append(receipt)

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return RollbackReceipt(
            receipt_id=receipt.receipt_id,
            rolled_back_at_utc=_utc_iso(),
            rollback_argv=(),
            exit_code=0,
            success=False,
            message=receipt.rollback_notes or "Terminated processes cannot be restarted automatically.",
        )


class BlockIpPlaybook:
    playbook_id = "block_ip"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_1_playbook"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        ip = validate_ip(params.get("ip", ""), blocked_ips=ctx.blocked_ips)
        return {"ip": ip}

    def _detect_firewall(self, ctx: HostContext) -> str:
        for tool in ("ufw", "nft", "iptables"):
            if ctx.which(tool):
                return tool
        return "ufw"

    def _commands_for(self, firewall: str, ip: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if firewall == "nft":
            return (
                ("sudo", "-n", "nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"),
                ("sudo", "-n", "nft", "list", "ruleset"),
            )
        if firewall == "iptables":
            return (
                ("sudo", "-n", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"),
                ("sudo", "-n", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"),
            )
        return (
            ("sudo", "-n", "ufw", "insert", "1", "deny", "from", ip, "to", "any"),
            ("sudo", "-n", "ufw", "delete", "deny", "from", ip, "to", "any"),
        )

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        ip = clean["ip"]
        fw = self._detect_firewall(ctx)
        if not ctx.which(fw):
            return PreflightReport(
                passed=False,
                requires_sudo=True,
                summary=f"[FAIL] No supported firewall binary (ufw/nft/iptables) found on host.",
            )
        check_argv = (
            ["sudo", "-n", "ufw", "status"]
            if fw == "ufw"
            else ["sudo", "-n", "nft", "list", "ruleset"]
            if fw == "nft"
            else ["sudo", "-n", "iptables", "-S", "INPUT"]
        )
        res = ctx.runner(check_argv, None)
        already = res.exit_code == 0 and ip in res.stdout
        return PreflightReport(
            passed=True,
            already_applied=already,
            requires_sudo=True,
            summary=(
                f"[PASS] Firewall '{fw}' detected; target IP {ip} validated"
                + (" (rule already present)" if already else "")
            ),
            details=(f"backend={fw}",),
            observed_state={"firewall": fw},
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        ip = clean["ip"]
        fw = self._detect_firewall(ctx)
        cmd, rollback = self._commands_for(fw, ip)
        return CommandOrDiffPreview(
            command_argv=cmd,
            rollback_argv=rollback,
            summary=f"Block inbound network traffic from {ip} using {fw}",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        preview = self.render_preview(clean, ctx)
        result = ctx.runner(preview.command_argv, sudo_password)
        receipt = _build_receipt(
            journal=journal,
            investigation_id=investigation_id,
            recommendation_id=recommendation_id,
            analysis_id=analysis_id,
            playbook_id=self.playbook_id,
            params=clean,
            ctx=ctx,
            command_argv=preview.command_argv,
            rollback_argv=preview.rollback_argv,
            result=result,
        )
        return journal.append(receipt)

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return _standard_rollback(receipt, ctx, sudo_password=sudo_password)


class KillProcessPlaybook:
    playbook_id = "kill_process"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_1_playbook"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        return {"pid": validate_pid(params.get("pid", ""))}

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        pid = clean["pid"]
        ps_res = ctx.runner(["ps", "-p", pid, "-o", "pid=,user=,comm="], None)
        if ps_res.exit_code != 0 or not ps_res.stdout:
            return PreflightReport(
                passed=False,
                already_applied=True,
                requires_sudo=True,
                summary=f"[FAIL] Process PID {pid} is not running.",
            )
        return PreflightReport(
            passed=True,
            requires_sudo=True,
            summary=f"[PASS] Process running: {ps_res.stdout}",
            observed_state={"process": ps_res.stdout},
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        pid = clean["pid"]
        return CommandOrDiffPreview(
            command_argv=("sudo", "-n", "kill", "-9", pid),
            rollback_argv=(),
            summary=f"Terminate process PID {pid}",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        preview = self.render_preview(clean, ctx)
        result = ctx.runner(preview.command_argv, sudo_password)
        receipt = _build_receipt(
            journal=journal,
            investigation_id=investigation_id,
            recommendation_id=recommendation_id,
            analysis_id=analysis_id,
            playbook_id=self.playbook_id,
            params=clean,
            ctx=ctx,
            command_argv=preview.command_argv,
            rollback_argv=(),
            result=result,
            rollback_notes=f"Killed PID {clean['pid']}; process termination cannot be undone automatically.",
        )
        return journal.append(receipt)

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return RollbackReceipt(
            receipt_id=receipt.receipt_id,
            rolled_back_at_utc=_utc_iso(),
            rollback_argv=(),
            success=False,
            message=receipt.rollback_notes or "Killed process cannot be restored automatically.",
        )


class FixFilePermissionsPlaybook:
    playbook_id = "fix_file_permissions"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_1_playbook"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        path, mode = validate_file_permission_params(
            params.get("path", ""), params.get("mode", "")
        )
        return {"path": path, "mode": mode}

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        path = Path(clean["path"])
        current = ctx.get_file_mode(path)
        if current is None:
            return PreflightReport(
                passed=False,
                requires_sudo=True,
                summary=f"[FAIL] File {clean['path']!r} not accessible or missing on host.",
            )
        current_oct = f"{current:04o}"
        already = current_oct == clean["mode"]
        return PreflightReport(
            passed=True,
            already_applied=already,
            requires_sudo=True,
            summary=(
                f"[PASS] {clean['path']} current mode={current_oct} -> target={clean['mode']}"
                + (" (already compliant)" if already else "")
            ),
            observed_state={"original_mode": current_oct},
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        current = ctx.get_file_mode(Path(clean["path"]))
        orig_oct = f"{current:04o}" if current is not None else clean["mode"]
        return CommandOrDiffPreview(
            command_argv=("sudo", "-n", "chmod", clean["mode"], clean["path"]),
            rollback_argv=("sudo", "-n", "chmod", orig_oct, clean["path"]),
            target_path=clean["path"],
            summary=f"Set permissions of {clean['path']} to {clean['mode']} (rollback: {orig_oct})",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        preview = self.render_preview(clean, ctx)
        result = ctx.runner(preview.command_argv, sudo_password)
        receipt = _build_receipt(
            journal=journal,
            investigation_id=investigation_id,
            recommendation_id=recommendation_id,
            analysis_id=analysis_id,
            playbook_id=self.playbook_id,
            params=clean,
            ctx=ctx,
            command_argv=preview.command_argv,
            rollback_argv=preview.rollback_argv,
            result=result,
        )
        return journal.append(receipt)

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return _standard_rollback(receipt, ctx, sudo_password=sudo_password)


# ---------------------------------------------------------------------------
# Tier 2 Guided Config & Patch Playbooks
# ---------------------------------------------------------------------------


def _apply_sshd_directive(original_text: str, directive: str, value: str) -> str:
    """Update or append ``directive value`` cleanly inside an sshd_config body."""
    pattern = re.compile(rf"^\s*#?\s*{re.escape(directive)}\b.*$", re.IGNORECASE)
    lines = original_text.splitlines()
    replaced = False
    new_lines: list[str] = []
    for line in lines:
        if not replaced and pattern.match(line):
            new_lines.append(f"{directive} {value}")
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(f"{directive} {value}")
    return "\n".join(new_lines) + "\n"


class HardenSshdConfigPlaybook:
    playbook_id = "harden_sshd_config"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_2_config_diff"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        directive, value = validate_sshd_params(
            params.get("directive", ""), params.get("value", "")
        )
        return {"directive": directive, "value": value}

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        content = ctx.read_text(ctx.sshd_config_path)
        if content is None:
            return PreflightReport(
                passed=False,
                requires_sudo=True,
                summary=f"[FAIL] Cannot read {ctx.sshd_config_path}.",
            )
        active_line = re.compile(
            rf"^\s*{re.escape(clean['directive'])}\s+{re.escape(clean['value'])}\s*$",
            re.IGNORECASE | re.MULTILINE,
        )
        already = bool(active_line.search(content))
        return PreflightReport(
            passed=True,
            already_applied=already,
            requires_sudo=True,
            summary=(
                f"[PASS] {ctx.sshd_config_path} readable; setting {clean['directive']} {clean['value']}"
                + (" (already set)" if already else "")
            ),
            details=(f"target={ctx.sshd_config_path}", "Will run `sudo sshd -t` before reloading."),
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        original = ctx.read_text(ctx.sshd_config_path) or ""
        updated = _apply_sshd_directive(original, clean["directive"], clean["value"])
        diff_lines = list(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"{ctx.sshd_config_path} (before)",
                tofile=f"{ctx.sshd_config_path} (after)",
            )
        )
        diff_text = "".join(diff_lines) or "(no diff — directive already set)"
        return CommandOrDiffPreview(
            command_argv=("sudo", "-n", "sshd", "-t"),
            rollback_argv=("sudo", "-n", "systemctl", "reload", "sshd"),
            unified_diff=diff_text,
            target_path=str(ctx.sshd_config_path),
            summary=f"Update {clean['directive']} -> {clean['value']} in {ctx.sshd_config_path}, validate with sshd -t, reload sshd",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        original = ctx.read_text(ctx.sshd_config_path)
        if original is None:
            fail_res = CommandResult(
                argv=("read", str(ctx.sshd_config_path)),
                exit_code=1,
                stderr=f"Cannot read {ctx.sshd_config_path}",
            )
            return journal.append(
                _build_receipt(
                    journal=journal,
                    investigation_id=investigation_id,
                    recommendation_id=recommendation_id,
                    analysis_id=analysis_id,
                    playbook_id=self.playbook_id,
                    params=clean,
                    ctx=ctx,
                    command_argv=("sudo", "-n", "sshd", "-t"),
                    rollback_argv=(),
                    result=fail_res,
                )
            )

        backup_path = journal.snapshot_text(original, label="sshd_config")
        updated = _apply_sshd_directive(original, clean["directive"], clean["value"])
        staged_path = journal.snapshot_text(updated, label="sshd_config.staged")

        install_argv = ("sudo", "-n", "cp", str(staged_path), str(ctx.sshd_config_path))
        restore_argv = ("sudo", "-n", "cp", str(backup_path), str(ctx.sshd_config_path))
        validate_argv = ("sudo", "-n", "sshd", "-t")
        reload_argv = ("sudo", "-n", "systemctl", "reload", "sshd")

        copy_res = ctx.runner(install_argv, sudo_password)
        if copy_res.exit_code != 0:
            return journal.append(
                _build_receipt(
                    journal=journal,
                    investigation_id=investigation_id,
                    recommendation_id=recommendation_id,
                    analysis_id=analysis_id,
                    playbook_id=self.playbook_id,
                    params=clean,
                    ctx=ctx,
                    command_argv=install_argv,
                    rollback_argv=restore_argv,
                    result=copy_res,
                    backup_path=str(backup_path),
                )
            )

        val_res = ctx.runner(validate_argv, sudo_password)
        if val_res.exit_code != 0:
            # Automatically restore backup if sshd -t fails!
            ctx.runner(restore_argv, sudo_password)
            failed = CommandResult(
                argv=validate_argv,
                exit_code=val_res.exit_code,
                stdout=val_res.stdout,
                stderr=f"sshd -t syntax validation failed (backup auto-restored): {val_res.stderr}",
            )
            return journal.append(
                _build_receipt(
                    journal=journal,
                    investigation_id=investigation_id,
                    recommendation_id=recommendation_id,
                    analysis_id=analysis_id,
                    playbook_id=self.playbook_id,
                    params=clean,
                    ctx=ctx,
                    command_argv=validate_argv,
                    rollback_argv=restore_argv,
                    result=failed,
                    backup_path=str(backup_path),
                )
            )

        reload_res = ctx.runner(reload_argv, sudo_password)
        return journal.append(
            _build_receipt(
                journal=journal,
                investigation_id=investigation_id,
                recommendation_id=recommendation_id,
                analysis_id=analysis_id,
                playbook_id=self.playbook_id,
                params=clean,
                ctx=ctx,
                command_argv=reload_argv,
                rollback_argv=restore_argv,
                result=reload_res,
                backup_path=str(backup_path),
            )
        )

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        if not receipt.backup_path:
            return RollbackReceipt(
                receipt_id=receipt.receipt_id,
                rolled_back_at_utc=_utc_iso(),
                rollback_argv=(),
                success=False,
                message="No backup snapshot path recorded for sshd_config rollback.",
            )
        restore_argv = ("sudo", "-n", "cp", receipt.backup_path, str(ctx.sshd_config_path))
        res = ctx.runner(restore_argv, sudo_password)
        if res.exit_code == 0:
            ctx.runner(("sudo", "-n", "systemctl", "reload", "sshd"), sudo_password)
        return RollbackReceipt(
            receipt_id=receipt.receipt_id,
            rolled_back_at_utc=_utc_iso(),
            rollback_argv=restore_argv,
            backup_restored=receipt.backup_path,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            success=res.exit_code == 0,
            message="Restored sshd_config backup and reloaded sshd." if res.exit_code == 0 else res.stderr,
        )


class QuarantineCronFilePlaybook:
    playbook_id = "quarantine_cron_file"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_2_config_diff"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        return {"path": validate_cron_file_path(params.get("path", ""))}

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        exists = ctx.read_text(Path(clean["path"])) is not None
        return PreflightReport(
            passed=exists,
            already_applied=not exists,
            requires_sudo=True,
            summary=(
                f"[PASS] Cron file {clean['path']} found for quarantine."
                if exists
                else f"[FAIL] Cron file {clean['path']} does not exist."
            ),
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        backup_dest = f"~/.forensiq/backups/{Path(clean['path']).name}.quarantine"
        return CommandOrDiffPreview(
            command_argv=("sudo", "-n", "mv", clean["path"], backup_dest),
            rollback_argv=("sudo", "-n", "mv", backup_dest, clean["path"]),
            target_path=clean["path"],
            summary=f"Quarantine cron file {clean['path']} into ForensIQ backups",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        journal._ensure_dirs()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = journal.backup_dir / f"{Path(clean['path']).name}.{stamp}.forensiq.bak"
        cmd = ("sudo", "-n", "mv", clean["path"], str(dest))
        rollback = ("sudo", "-n", "mv", str(dest), clean["path"])
        res = ctx.runner(cmd, sudo_password)
        return journal.append(
            _build_receipt(
                journal=journal,
                investigation_id=investigation_id,
                recommendation_id=recommendation_id,
                analysis_id=analysis_id,
                playbook_id=self.playbook_id,
                params=clean,
                ctx=ctx,
                command_argv=cmd,
                rollback_argv=rollback,
                result=res,
                backup_path=str(dest),
            )
        )

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return _standard_rollback(receipt, ctx, sudo_password=sudo_password)


class UpgradePackagePlaybook:
    playbook_id = "upgrade_package"
    tier: Literal["tier_1_playbook", "tier_2_config_diff"] = "tier_2_config_diff"

    def validate_params(self, params: Mapping[str, str], ctx: HostContext) -> dict[str, str]:
        return {"package": validate_package_name(params.get("package", ""))}

    def _detect_pkg_mgr(self, ctx: HostContext) -> str:
        for mgr in ("apt-get", "dnf", "pacman"):
            if ctx.which(mgr):
                return mgr
        return "apt-get"

    def _upgrade_argv(self, mgr: str, package: str) -> tuple[str, ...]:
        if mgr == "dnf":
            return ("sudo", "-n", "dnf", "upgrade", "-y", package)
        if mgr == "pacman":
            return ("sudo", "-n", "pacman", "-S", "--noconfirm", package)
        return ("sudo", "-n", "apt-get", "install", "--only-upgrade", "-y", package)

    def preflight_check(self, params: Mapping[str, str], ctx: HostContext) -> PreflightReport:
        clean = self.validate_params(params, ctx)
        mgr = self._detect_pkg_mgr(ctx)
        if not ctx.which(mgr):
            return PreflightReport(
                passed=False,
                requires_sudo=True,
                summary="[FAIL] No supported package manager (apt-get/dnf/pacman) detected.",
            )
        return PreflightReport(
            passed=True,
            requires_sudo=True,
            summary=f"[PASS] Package manager '{mgr}' ready to upgrade {clean['package']!r}.",
            observed_state={"package_manager": mgr},
        )

    def render_preview(self, params: Mapping[str, str], ctx: HostContext) -> CommandOrDiffPreview:
        clean = self.validate_params(params, ctx)
        mgr = self._detect_pkg_mgr(ctx)
        return CommandOrDiffPreview(
            command_argv=self._upgrade_argv(mgr, clean["package"]),
            rollback_argv=(),
            summary=f"Upgrade package {clean['package']!r} via {mgr}",
        )

    def execute(
        self,
        params: Mapping[str, str],
        journal: RollbackJournal,
        ctx: HostContext,
        *,
        investigation_id: str,
        recommendation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        clean = self.validate_params(params, ctx)
        preview = self.render_preview(clean, ctx)
        res = ctx.runner(preview.command_argv, sudo_password)
        return journal.append(
            _build_receipt(
                journal=journal,
                investigation_id=investigation_id,
                recommendation_id=recommendation_id,
                analysis_id=analysis_id,
                playbook_id=self.playbook_id,
                params=clean,
                ctx=ctx,
                command_argv=preview.command_argv,
                rollback_argv=(),
                result=res,
                rollback_notes="Use OS package manager downgrade/snapshot to revert package upgrades.",
            )
        )

    def rollback(
        self, receipt: ExecutionReceipt, ctx: HostContext, *, sudo_password: str | None = None
    ) -> RollbackReceipt:
        return RollbackReceipt(
            receipt_id=receipt.receipt_id,
            rolled_back_at_utc=_utc_iso(),
            rollback_argv=(),
            success=False,
            message=receipt.rollback_notes or "Package downgrade must be performed manually.",
        )


PLAYBOOK_REGISTRY: dict[str, RemediationPlaybook] = {
    "lock_user": LockUserPlaybook(),
    "terminate_user_sessions": TerminateUserSessionsPlaybook(),
    "block_ip": BlockIpPlaybook(),
    "kill_process": KillProcessPlaybook(),
    "fix_file_permissions": FixFilePermissionsPlaybook(),
    "harden_sshd_config": HardenSshdConfigPlaybook(),
    "quarantine_cron_file": QuarantineCronFilePlaybook(),
    "upgrade_package": UpgradePackagePlaybook(),
}
