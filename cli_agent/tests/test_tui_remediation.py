"""Headless Textual UI tests for the HITL Remediation workflow (view 7 + modals)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Sequence

from textual.widgets import DataTable, Input, Label, RichLog

from cli_agent.remediation import HostContext, RemediationEngine, RollbackJournal
from cli_agent.remediation.models import CommandResult
from cli_agent.services.auth_service import Session, TokenStore
from cli_agent.services.cli_service import CliService
from cli_agent.services.collector_service import CollectorService
from cli_agent.services.config_service import ConfigService
from cli_agent.tui.app import ForensIQApp
from cli_agent.tui.remediation_modals import (
    RejectReasonScreen,
    RemediationConfirmScreen,
    RollbackConfirmScreen,
)

from .conftest import FakeExtractor, FakeTransport, make_jwt, wait_for


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], str | None]] = []

    def __call__(
        self,
        argv: Sequence[str],
        sudo_password: str | None = None,
    ) -> CommandResult:
        self.calls.append((tuple(argv), sudo_password))
        return CommandResult(argv=tuple(argv), exit_code=0, stdout="ok", stderr="")


def _sample_latest_payload() -> dict:
    return {
        "analysis": {
            "id": "analysis-42",
            "summary": "SSH brute force from 185.220.101.4 targeting alice",
            "matched_techniques": [
                {"technique_id": "T1110.001", "name": "Password Guessing", "relevance_score": 0.91}
            ],
            "investigation": {
                "investigation_id": "inv-tui-001",
                "executive_summary": "Brute force followed by suspicious login.",
                "findings": [{"finding_id": "f-001", "title": "SSH brute force"}],
                "recommendations": [
                    {
                        "recommendation_id": "rec-001",
                        "priority": "immediate",
                        "title": "Block attacker IP 185.220.101.4",
                        "target": "185.220.101.4",
                        "action": "Block inbound traffic from 185.220.101.4",
                        "expected_effect": "Stop brute-force attempts.",
                        "supporting_finding_ids": ["f-001"],
                        "evidence_event_ids": ["evt-001"],
                        "knowledge_mitigation_ids": ["M1030"],
                        "requires_human_approval": True,
                        "auto_executable": False,
                        "rollback_notes": "ufw delete deny from 185.220.101.4",
                        "fixable_via_tui": True,
                        "fix_tier": "tier_1_playbook",
                        "playbook_id": "block_ip",
                        "playbook_params": {"ip": "185.220.101.4"},
                        "execution_status": "pending_approval",
                    },
                    {
                        "recommendation_id": "rec-002",
                        "priority": "immediate",
                        "title": "Lock compromised account alice",
                        "target": "alice",
                        "action": "Lock local account alice",
                        "expected_effect": "Prevent further SSH sessions.",
                        "supporting_finding_ids": ["f-001"],
                        "evidence_event_ids": ["evt-001"],
                        "knowledge_mitigation_ids": ["M1018"],
                        "requires_human_approval": True,
                        "auto_executable": False,
                        "rollback_notes": "usermod -U alice",
                        "fixable_via_tui": True,
                        "fix_tier": "tier_1_playbook",
                        "playbook_id": "lock_user",
                        "playbook_params": {"username": "alice"},
                        "execution_status": "pending_approval",
                    },
                    {
                        "recommendation_id": "rec-003",
                        "priority": "long_term",
                        "title": "Rotate enterprise Kerberos keys",
                        "target": "Active Directory",
                        "action": "Coordinate domain-wide krbtgt rotation with IAM",
                        "expected_effect": "Invalidate Golden Tickets.",
                        "supporting_finding_ids": ["f-001"],
                        "evidence_event_ids": ["evt-001"],
                        "knowledge_mitigation_ids": [],
                        "requires_human_approval": True,
                        "auto_executable": False,
                        "rollback_notes": "N/A",
                        "fixable_via_tui": False,
                        "fix_tier": "tier_3_advisory",
                        "playbook_id": "manual_only",
                        "playbook_params": {},
                        "execution_status": "pending_approval",
                    },
                ],
            },
        }
    }


def _build_remediation_app(tmp_path: Path, transport: FakeTransport, runner: _FakeRunner) -> ForensIQApp:
    store = TokenStore(tmp_path / "session.json")
    store.save(
        Session(
            access_token=make_jwt(),
            username="analyst",
            expires_at=time.time() + 3600,
        )
    )
    ctx = HostContext(
        current_user="analyst",
        runner=runner,
        user_lookup=lambda u: (1001, "/bin/bash") if u == "alice" else None,
        which=lambda name: f"/usr/sbin/{name}" if name in ("ufw", "usermod") else None,
    )
    home = tmp_path / "forensiq_home"
    engine = RemediationEngine(
        journal=RollbackJournal(
            journal_path=home / "remediation_journal.json",
            backup_dir=home / "backups",
        ),
        host_context=ctx,
    )
    service = CliService(
        config_service=ConfigService(tmp_path / "config.json"),
        token_store=store,
        transport=transport,
        collector=CollectorService(extractor=FakeExtractor()),
        remediation=engine,
    )
    return ForensIQApp(service=service, auto_probe=False)


def _stream_text(app: ForensIQApp) -> str:
    log = app.query_one("#stream", RichLog)
    return "\n".join(line.text for line in log.lines)


def _detail_text(app: ForensIQApp) -> str:
    log = app.query_one("#detail-view", RichLog)
    return "\n".join(line.text for line in log.lines)


async def test_hitl_remediation_full_lifecycle_approve_reject_advisory_and_undo(tmp_path: Path) -> None:
    transport = FakeTransport().queue(
        {"status": "healthy", "services": {"mongodb": "ok"}},  # GET /health on pressing 7
        _sample_latest_payload(),  # GET /api/v1/latest
        {"status": "ok", "execution_status": "executed"},  # POST remediation-status after approve
        {"status": "ok", "execution_status": "rejected"},  # POST remediation-status after reject
        {"status": "ok", "execution_status": "rolled_back"},  # POST remediation-status after undo
    )
    runner = _FakeRunner()
    app = _build_remediation_app(tmp_path, transport, runner)

    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("7")
        assert await wait_for(lambda: len(app.state.remediation_items) == 3)
        await pilot.pause()

        assert app.view == "remediation"
        assert "Remediation (2)" in str(app.query_one("#nav-label-remediation", Label).content)
        table = app.query_one("#techniques", DataTable)
        assert table.row_count == 3

        # 1. Dry-run [D] on rec-001 (ufw preflight runs read-only `ufw status` check)
        await pilot.press("d")
        assert await wait_for(lambda: "rec-001" in app.state.remediation_preflight)
        await pilot.pause()
        assert "ufw insert 1 deny from 185.220.101.4 to any" in _detail_text(app)
        assert not any("deny" in call[0] for call in runner.calls)  # Dry-run never runs mutating deny

        # 2. Approve [A] on rec-001 -> opens RemediationConfirmScreen
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, RemediationConfirmScreen)

        pwd_input = app.screen.query_one("#remediation-sudo-password", Input)
        pwd_input.value = "super-secret-sudo-pw"
        await pilot.click("#btn-confirm-fix")
        assert await wait_for(lambda: app.state.remediation_items[0].execution_status == "executed")
        await pilot.pause()

        assert not isinstance(app.screen, RemediationConfirmScreen)
        deny_calls = [call for call in runner.calls if "deny" in call[0] and "delete" not in call[0]]
        assert len(deny_calls) == 1
        assert deny_calls[0][0] == ("sudo", "-n", "ufw", "insert", "1", "deny", "from", "185.220.101.4", "to", "any")
        assert deny_calls[0][1] == "super-secret-sudo-pw"
        # Password must NEVER appear in stream, detail view, or journal file on disk
        assert "super-secret-sudo-pw" not in _stream_text(app)
        assert "super-secret-sudo-pw" not in _detail_text(app)
        journal_text = (tmp_path / "forensiq_home" / "remediation_journal.json").read_text(encoding="utf-8")
        assert "super-secret-sudo-pw" not in journal_text
        assert "Remediation (1)" in str(app.query_one("#nav-label-remediation", Label).content)
        assert any(
            req["url"].endswith("/api/v1/history/analysis-42/remediation-status")
            for req in transport.requests
        )

        # 3. Select rec-002 (index 1) and Reject [R]
        app.state.selected_remediation_index = 1
        app._render_page()
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, RejectReasonScreen)
        app.screen.query_one("#reject-reason", Input).value = "approved maintenance window"
        await pilot.click("#btn-confirm-reject")
        assert await wait_for(lambda: app.state.remediation_items[1].execution_status == "rejected")
        await pilot.pause()
        assert "Remediation (0)" not in str(app.query_one("#nav-label-remediation", Label).content)
        assert str(app.query_one("#nav-label-remediation", Label).content) == "7  Remediation"

        # 4. Select rec-003 (Tier 3 advisory) and press [A] -> blocked without modal
        app.state.selected_remediation_index = 2
        app._render_page()
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        assert not isinstance(app.screen, RemediationConfirmScreen)
        assert "[ADVISORY_ONLY]" in _stream_text(app)

        # 5. Undo [U] -> opens RollbackConfirmScreen and reverts rec-001
        app.state.selected_remediation_index = 0
        app._render_page()
        await pilot.pause()
        await pilot.press("u")
        await pilot.pause()
        assert isinstance(app.screen, RollbackConfirmScreen)
        await pilot.click("#btn-confirm-rollback")
        assert await wait_for(lambda: app.state.remediation_items[0].execution_status == "rolled_back")
        await pilot.pause()
        assert runner.calls[-1][0] == ("sudo", "-n", "ufw", "delete", "deny", "from", "185.220.101.4", "to", "any")


async def test_remediation_view_survives_80x24_terminal(tmp_path: Path) -> None:
    transport = FakeTransport().queue(
        {"status": "healthy", "services": {}},
        _sample_latest_payload(),
    )
    app = _build_remediation_app(tmp_path, transport, _FakeRunner())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("7")
        assert await wait_for(lambda: len(app.state.remediation_items) == 3)
        await pilot.pause()
        assert app.query_one("#monitor-panel").size.width > 0
        assert app.query_one("#technique-panel").size.width > 0
        assert app.query_one("#remediation-controls").display is True
