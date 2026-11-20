"""High-level HITL RemediationEngine coordinating playbooks, validation, and rollback journal."""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping
from urllib.parse import urlsplit

from .journal import RollbackJournal
from .models import (
    CommandOrDiffPreview,
    ExecutionReceipt,
    PreflightReport,
    RemediationItemView,
    RollbackReceipt,
)
from .playbooks import PLAYBOOK_REGISTRY, HostContext, RemediationPlaybook


def extract_backend_ips(base_url: str) -> tuple[str, ...]:
    """Extract literal IP host from ``base_url`` so ``block_ip`` refuses blocking the backend."""
    host = (urlsplit(base_url).hostname or "").strip()
    if not host:
        return ()
    try:
        return (str(ipaddress.ip_address(host)),)
    except ValueError:
        return ()


class RemediationEngine:
    """Local execution & rollback facade owned by the CLI/TUI (never auto-executes)."""

    def __init__(
        self,
        *,
        journal: RollbackJournal | None = None,
        host_context: HostContext | None = None,
        registry: Mapping[str, RemediationPlaybook] | None = None,
        backend_base_url: str = "",
    ) -> None:
        self.journal = journal or RollbackJournal()
        self.registry: dict[str, RemediationPlaybook] = (
            dict(registry) if registry is not None else dict(PLAYBOOK_REGISTRY)
        )
        if host_context is not None:
            self.ctx = host_context
        else:
            self.ctx = HostContext(blocked_ips=extract_backend_ips(backend_base_url))

    def set_backend_url(self, base_url: str) -> None:
        """Keep backend host IP protected from accidental ``block_ip`` rules."""
        self.ctx.blocked_ips = extract_backend_ips(base_url)

    def extract_recommendations(
        self,
        investigation: Mapping[str, Any] | None,
    ) -> list[RemediationItemView]:
        """Convert backend ``investigation['recommendations']`` into ``RemediationItemView`` items."""
        if not isinstance(investigation, Mapping):
            return []
        raw_recs = investigation.get("recommendations")
        if not isinstance(raw_recs, list):
            return []
        items: list[RemediationItemView] = []
        for idx, rec in enumerate(raw_recs, start=1):
            if isinstance(rec, Mapping):
                items.append(RemediationItemView.from_mapping(rec, index=idx))
        return items

    def get_playbook(self, playbook_id: str) -> RemediationPlaybook:
        playbook = self.registry.get(playbook_id)
        if playbook is None:
            raise ValueError(f"Playbook {playbook_id!r} is not registered locally (advisory only).")
        return playbook

    def validate(self, item: RemediationItemView) -> dict[str, str]:
        if not item.is_executable_locally:
            raise ValueError(
                f"Recommendation {item.recommendation_id} is advisory-only ({item.playbook_id})."
            )
        playbook = self.get_playbook(item.playbook_id)
        return playbook.validate_params(item.playbook_params, self.ctx)

    def preview(self, item: RemediationItemView) -> CommandOrDiffPreview:
        if not item.is_executable_locally:
            return CommandOrDiffPreview(
                summary="Advisory / manual runbook only — cannot be executed automatically from the TUI."
            )
        playbook = self.get_playbook(item.playbook_id)
        clean = playbook.validate_params(item.playbook_params, self.ctx)
        return playbook.render_preview(clean, self.ctx)

    def dry_run(self, item: RemediationItemView) -> tuple[PreflightReport, CommandOrDiffPreview]:
        if not item.is_executable_locally:
            return (
                PreflightReport(
                    passed=False,
                    requires_sudo=False,
                    summary="[ADVISORY_ONLY] No local TUI playbook applies; follow manual runbook.",
                ),
                self.preview(item),
            )
        playbook = self.get_playbook(item.playbook_id)
        clean = playbook.validate_params(item.playbook_params, self.ctx)
        report = playbook.preflight_check(clean, self.ctx)
        preview = playbook.render_preview(clean, self.ctx)
        return report, preview

    def execute(
        self,
        item: RemediationItemView,
        *,
        investigation_id: str,
        analysis_id: str | None = None,
        sudo_password: str | None = None,
    ) -> ExecutionReceipt:
        """Execute a validated Tier-1 or Tier-2 playbook AFTER explicit human approval."""
        if not item.is_executable_locally:
            raise ValueError(
                f"Cannot execute Tier-3 advisory recommendation {item.recommendation_id}."
            )
        playbook = self.get_playbook(item.playbook_id)
        clean = playbook.validate_params(item.playbook_params, self.ctx)
        receipt = playbook.execute(
            clean,
            self.journal,
            self.ctx,
            investigation_id=investigation_id,
            recommendation_id=item.recommendation_id,
            analysis_id=analysis_id,
            sudo_password=sudo_password,
        )
        item.execution_status = receipt.status
        return receipt

    def rollback(
        self,
        receipt_id: str,
        *,
        sudo_password: str | None = None,
    ) -> RollbackReceipt:
        """Revert an executed receipt recorded in the local RollbackJournal."""
        receipt = self.journal.get_receipt(receipt_id)
        if receipt is None:
            raise ValueError(f"Rollback receipt {receipt_id!r} not found in local journal.")
        playbook = self.get_playbook(receipt.playbook_id)
        rb = playbook.rollback(receipt, self.ctx, sudo_password=sudo_password)
        self.journal.mark_rolled_back(receipt_id, rb)
        return rb

    def list_journal(self, *, limit: int = 50) -> list[ExecutionReceipt]:
        return self.journal.list_receipts(limit=limit)
