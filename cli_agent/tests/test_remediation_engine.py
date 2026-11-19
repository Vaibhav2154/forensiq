"""Tests for the local HITL remediation validators, playbooks, engine, and rollback journal."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import pytest

from cli_agent.remediation import (
    HostContext,
    RemediationEngine,
    RemediationItemView,
    RollbackJournal,
)
from cli_agent.remediation.models import CommandResult
from cli_agent.remediation.validators import (
    validate_cron_file_path,
    validate_file_permission_params,
    validate_ip,
    validate_package_name,
    validate_pid,
    validate_sshd_params,
    validate_username,
)


class _RecordingRunner:
    """Deterministic fake subprocess runner enforcing tuple-argv (shell=False) discipline."""

    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self._responses = responses or {}

    def __call__(
        self,
        argv: Sequence[str],
        sudo_password: str | None = None,
    ) -> CommandResult:
        assert not isinstance(argv, (str, bytes)), "argv must be a sequence, never a shell string"
        tuple_argv = tuple(argv)
        self.calls.append((tuple_argv, sudo_password))
        key = " ".join(tuple_argv)
        for pattern, result in self._responses.items():
            if pattern in key:
                return result
        return CommandResult(argv=tuple_argv, exit_code=0, stdout="ok", stderr="")


# -- Validators & anti-prompt-injection ----------------------------------
@pytest.mark.parametrize(
    "bad_ip",
    [
        "127.0.0.1",
        "::1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "185.220.101.4; rm -rf /",
        "$(whoami)",
        "not-an-ip",
    ],
)
def test_validate_ip_rejects_unsafe_and_injected_values(bad_ip: str) -> None:
    with pytest.raises(ValueError):
        validate_ip(bad_ip)


def test_validate_ip_blocks_backend_host_ip() -> None:
    assert validate_ip("185.220.101.4", blocked_ips=("10.0.0.5",)) == "185.220.101.4"
    with pytest.raises(ValueError, match="backend"):
        validate_ip("10.0.0.5", blocked_ips=("10.0.0.5",))


@pytest.mark.parametrize(
    "bad_user",
    [
        "root",
        "nobody",
        "alice; id",
        "alice && reboot",
        "../etc/passwd",
        "UPPERCASE",
        "",
    ],
)
def test_validate_username_rejects_protected_and_injected_values(bad_user: str) -> None:
    with pytest.raises(ValueError):
        validate_username(bad_user, current_user="analyst")


def test_validate_username_rejects_current_operator() -> None:
    assert validate_username("alice", current_user="analyst") == "alice"
    with pytest.raises(ValueError, match="current analyst"):
        validate_username("analyst", current_user="analyst")


def test_other_validators_enforce_strict_allowlists() -> None:
    assert validate_pid("4242") == "4242"
    with pytest.raises(ValueError):
        validate_pid("1")
    with pytest.raises(ValueError):
        validate_pid("4242; kill -9 1")

    assert validate_file_permission_params("/etc/shadow", "0600") == ("/etc/shadow", "0600")
    with pytest.raises(ValueError):
        validate_file_permission_params("/etc/arbitrary", "0600")
    with pytest.raises(ValueError):
        validate_file_permission_params("/etc/shadow", "0777")

    assert validate_sshd_params("PasswordAuthentication", "no") == ("PasswordAuthentication", "no")
    with pytest.raises(ValueError):
        validate_sshd_params("PermitRootLogin", "yes")
    with pytest.raises(ValueError):
        validate_sshd_params("AuthorizedKeysCommand", "/bin/sh")

    assert validate_cron_file_path("/etc/cron.d/backdoor") == "/etc/cron.d/backdoor"
    with pytest.raises(ValueError):
        validate_cron_file_path("/etc/cron.d/../passwd")

    assert validate_package_name("openssh-server") == "openssh-server"
    with pytest.raises(ValueError):
        validate_package_name("openssh-server; curl evil")


# -- Playbook Engine & Rollback Journal ----------------------------------
def _make_item(playbook_id: str, params: dict[str, str], fix_tier: str = "tier_1_playbook") -> RemediationItemView:
    return RemediationItemView(
        recommendation_id="rec-001",
        title=f"Run {playbook_id}",
        priority="immediate",
        target=next(iter(params.values()), "host"),
        action="Structured playbook execution",
        fixable_via_tui=playbook_id != "manual_only",
        fix_tier=fix_tier,  # type: ignore[arg-type]
        playbook_id=playbook_id,  # type: ignore[arg-type]
        playbook_params=params,
    )


def _make_journal(base: Path) -> RollbackJournal:
    return RollbackJournal(
        journal_path=base / "remediation_journal.json",
        backup_dir=base / "backups",
    )


def test_block_ip_preflight_execute_and_rollback(tmp_path: Path) -> None:
    runner = _RecordingRunner()
    ctx = HostContext(
        current_user="analyst",
        blocked_ips=("10.0.0.5",),
        runner=runner,
        which=lambda name: f"/usr/sbin/{name}" if name == "ufw" else None,
    )
    journal = _make_journal(tmp_path)
    engine = RemediationEngine(journal=journal, host_context=ctx)
    item = _make_item("block_ip", {"ip": "185.220.101.4"})

    report, preview = engine.dry_run(item)
    assert report.passed is True
    assert preview.command_argv == ("sudo", "-n", "ufw", "insert", "1", "deny", "from", "185.220.101.4", "to", "any")
    assert preview.rollback_argv == ("sudo", "-n", "ufw", "delete", "deny", "from", "185.220.101.4", "to", "any")

    receipt = engine.execute(item, investigation_id="inv-1", analysis_id="ana-1")
    assert receipt.status == "executed"
    assert item.execution_status == "executed"
    assert len(journal.list_receipts()) == 1
    assert (tmp_path / "remediation_journal.json").exists()

    rb = engine.rollback(receipt.receipt_id)
    assert rb.success is True
    assert journal.get_receipt(receipt.receipt_id).status == "rolled_back"
    assert runner.calls[-1][0] == ("sudo", "-n", "ufw", "delete", "deny", "from", "185.220.101.4", "to", "any")


def test_lock_user_terminate_sessions_kill_process_and_chmod(tmp_path: Path) -> None:
    runner = _RecordingRunner()
    ctx = HostContext(
        current_user="analyst",
        runner=runner,
        user_lookup=lambda u: (1001, "/bin/bash") if u == "alice" else None,
        stat_mode=lambda p: 0o644 if p == Path("/etc/shadow") else None,
        which=lambda name: f"/usr/bin/{name}",
    )
    journal = _make_journal(tmp_path)
    engine = RemediationEngine(journal=journal, host_context=ctx)

    # lock_user
    lock_item = _make_item("lock_user", {"username": "alice"})
    r1 = engine.execute(lock_item, investigation_id="inv-2")
    assert r1.status == "executed"
    assert r1.command_argv == ["sudo", "-n", "usermod", "-L", "alice"]
    assert r1.rollback_argv == ["sudo", "-n", "usermod", "-U", "alice"]
    rb1 = engine.rollback(r1.receipt_id)
    assert rb1.success is True

    # terminate_user_sessions
    term_item = _make_item("terminate_user_sessions", {"username": "alice"})
    r2 = engine.execute(term_item, investigation_id="inv-2")
    assert r2.status == "executed"
    assert r2.command_argv == ["sudo", "-n", "pkill", "-KILL", "-u", "alice"]

    # kill_process
    kill_item = _make_item("kill_process", {"pid": "4242"})
    r3 = engine.execute(kill_item, investigation_id="inv-2")
    assert r3.status == "executed"
    assert r3.command_argv == ["sudo", "-n", "kill", "-9", "4242"]

    # fix_file_permissions captures original mode 0644 for rollback
    chmod_item = _make_item("fix_file_permissions", {"path": "/etc/shadow", "mode": "0600"})
    r4 = engine.execute(chmod_item, investigation_id="inv-2")
    assert r4.status == "executed"
    assert r4.command_argv == ["sudo", "-n", "chmod", "0600", "/etc/shadow"]
    assert r4.rollback_argv == ["sudo", "-n", "chmod", "0644", "/etc/shadow"]


def test_harden_sshd_config_unified_diff_backup_and_syntax_rollback(tmp_path: Path) -> None:
    sshd_content = "# OpenSSH Server Config\nPort 22\nPasswordAuthentication yes\n"

    # Case 1: sshd -t succeeds -> backup stored, rollback restores backup
    runner_ok = _RecordingRunner()
    ctx_ok = HostContext(
        current_user="analyst",
        runner=runner_ok,
        read_file=lambda p: sshd_content if p == Path("/etc/ssh/sshd_config") else "",
        which=lambda name: f"/usr/sbin/{name}",
    )
    journal = _make_journal(tmp_path / "ok")
    engine = RemediationEngine(journal=journal, host_context=ctx_ok)
    item = _make_item(
        "harden_sshd_config",
        {"directive": "PasswordAuthentication", "value": "no"},
        fix_tier="tier_2_config_diff",
    )
    report, preview = engine.dry_run(item)
    assert report.passed is True
    assert preview.unified_diff is not None
    assert "-PasswordAuthentication yes" in preview.unified_diff
    assert "+PasswordAuthentication no" in preview.unified_diff

    receipt = engine.execute(item, investigation_id="inv-3")
    assert receipt.status == "executed"
    assert receipt.backup_path is not None
    assert Path(receipt.backup_path).read_text(encoding="utf-8") == sshd_content

    rb = engine.rollback(receipt.receipt_id)
    assert rb.success is True
    assert rb.backup_restored == receipt.backup_path

    # Case 2: sshd -t fails -> automatically restores backup and marks receipt failed
    runner_fail = _RecordingRunner(
        responses={
            "sshd -t": CommandResult(
                argv=("sudo", "-n", "sshd", "-t"),
                exit_code=1,
                stdout="",
                stderr="Bad configuration option",
            )
        }
    )
    ctx_fail = HostContext(
        current_user="analyst",
        runner=runner_fail,
        read_file=lambda p: sshd_content if p == Path("/etc/ssh/sshd_config") else "",
        which=lambda name: f"/usr/sbin/{name}",
    )
    engine_fail = RemediationEngine(
        journal=_make_journal(tmp_path / "fail"),
        host_context=ctx_fail,
    )
    item_fail = _make_item(
        "harden_sshd_config",
        {"directive": "PasswordAuthentication", "value": "no"},
        fix_tier="tier_2_config_diff",
    )
    failed_receipt = engine_fail.execute(item_fail, investigation_id="inv-3")
    assert failed_receipt.status == "failed"
    assert "auto-restored" in failed_receipt.stderr
    assert any("cp" in call[0] and str(Path("/etc/ssh/sshd_config")) in call[0] for call in runner_fail.calls)


def test_quarantine_cron_and_upgrade_package_and_advisory_guard(tmp_path: Path) -> None:
    runner = _RecordingRunner()
    ctx = HostContext(
        current_user="analyst",
        runner=runner,
        which=lambda name: "/usr/bin/apt-get" if name == "apt-get" else None,
    )
    engine = RemediationEngine(journal=_make_journal(tmp_path), host_context=ctx)

    cron_item = _make_item(
        "quarantine_cron_file",
        {"path": "/etc/cron.d/backdoor"},
        fix_tier="tier_2_config_diff",
    )
    cron_rcpt = engine.execute(cron_item, investigation_id="inv-4")
    assert cron_rcpt.status == "executed"
    assert "mv" in cron_rcpt.command_argv
    assert "mv" in cron_rcpt.rollback_argv

    pkg_item = _make_item(
        "upgrade_package",
        {"package": "openssh-server"},
        fix_tier="tier_2_config_diff",
    )
    pkg_rcpt = engine.execute(pkg_item, investigation_id="inv-4")
    assert pkg_rcpt.status == "executed"
    assert pkg_rcpt.command_argv == ["sudo", "-n", "apt-get", "install", "--only-upgrade", "-y", "openssh-server"]

    advisory = _make_item("manual_only", {}, fix_tier="tier_3_advisory")
    with pytest.raises(ValueError, match="advisory"):
        engine.execute(advisory, investigation_id="inv-4")
