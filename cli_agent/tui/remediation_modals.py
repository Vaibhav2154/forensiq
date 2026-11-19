"""Human-in-the-Loop confirmation modals for local TUI remediation & rollback.

All visual styling lives in ``styles.tcss`` via semantic ``$fq-*`` variables.
Passwords entered into ``Input(password=True)`` are cleared in ``finally:``
blocks before dismissal and are never written to disk or event logs.
"""

from __future__ import annotations

import shlex

from rich.markup import escape
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RichLog, Static

from ..remediation.models import (
    CommandOrDiffPreview,
    ExecutionReceipt,
    PreflightReport,
    RemediationItemView,
)


def _format_argv(argv: tuple[str, ...] | list[str]) -> str:
    if not argv:
        return "(none)"
    return " ".join(shlex.quote(str(part)) for part in argv)


class RemediationConfirmScreen(ModalScreen[tuple[bool, str | None]]):
    """Explicit human confirmation modal before executing a local playbook."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self,
        item: RemediationItemView,
        preview: CommandOrDiffPreview,
        preflight: PreflightReport | None = None,
    ) -> None:
        super().__init__()
        self._item = item
        self._preview = preview
        self._preflight = preflight

    def compose(self) -> ComposeResult:
        requires_sudo = True if self._preflight is None else self._preflight.requires_sudo
        with Vertical(id="remediation-modal-box"):
            yield Label("APPROVE & EXECUTE LOCAL FIX", classes="panel-title")
            yield Static(
                f"recommendation  {escape(self._item.recommendation_id)}  ({escape(self._item.tier_label)} · {escape(self._item.playbook_id)})\n"
                f"title           {escape(self._item.title)}\n"
                f"target          {escape(self._item.target)}",
                classes="kv",
            )
            with VerticalScroll(id="remediation-preview-scroll"):
                yield RichLog(id="remediation-preview-log", markup=False, wrap=True)
            yield Static(
                f"rollback        {escape(_format_argv(self._preview.rollback_argv) if self._preview.rollback_argv else (self._item.rollback_notes or 'see local journal'))}",
                classes="kv",
            )
            if requires_sudo:
                yield Label("sudo password (kept in memory only; blank if root / NOPASSWD)", classes="field-label")
                yield Input(
                    placeholder="sudo password (optional)",
                    password=True,
                    id="remediation-sudo-password",
                )
            with Horizontal(id="remediation-modal-actions"):
                yield Button("Confirm & Execute", id="btn-confirm-fix", variant="success")
                yield Button("Cancel", id="btn-cancel-fix")

    def on_mount(self) -> None:
        log = self.query_one("#remediation-preview-log", RichLog)
        if self._preflight is not None:
            status = "PASS" if self._preflight.passed else "WARN"
            log.write(f"PRE-FLIGHT [{status}]: {self._preflight.summary}")
            for detail in self._preflight.details:
                log.write(f"  - {detail}")
            log.write("")
        if self._preview.command_argv:
            log.write("EXACT COMMAND (shell=False):")
            log.write(f"  {_format_argv(self._preview.command_argv)}")
        if self._preview.unified_diff:
            log.write("")
            log.write("UNIFIED DIFF:")
            log.write(self._preview.unified_diff)
        if self._preview.summary:
            log.write("")
            log.write(f"SUMMARY: {self._preview.summary}")
        inputs = self.query("#remediation-sudo-password")
        if inputs:
            inputs.first(Input).focus()
        else:
            self.query_one("#btn-confirm-fix", Button).focus()

    def _clear_password_input(self) -> None:
        inputs = self.query("#remediation-sudo-password")
        if inputs:
            inputs.first(Input).value = ""

    def _confirm(self) -> None:
        password: str | None = None
        try:
            inputs = self.query("#remediation-sudo-password")
            if inputs:
                raw = inputs.first(Input).value
                password = raw if raw else None
        finally:
            self._clear_password_input()
        self.dismiss((True, password))

    def action_cancel(self) -> None:
        self._clear_password_input()
        self.dismiss((False, None))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-confirm-fix":
            self._confirm()
        elif event.button.id == "btn-cancel-fix":
            self.action_cancel()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._confirm()


class RollbackConfirmScreen(ModalScreen[tuple[bool, str | None]]):
    """Explicit human confirmation modal before reverting a journaled fix."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, receipt: ExecutionReceipt) -> None:
        super().__init__()
        self._receipt = receipt

    def compose(self) -> ComposeResult:
        with Vertical(id="remediation-modal-box"):
            yield Label("CONFIRM ROLLBACK / UNDO", classes="panel-title")
            yield Static(
                f"receipt         {escape(self._receipt.receipt_id)}\n"
                f"recommendation  {escape(self._receipt.recommendation_id)}\n"
                f"playbook        {escape(self._receipt.playbook_id)}\n"
                f"executed at     {escape(self._receipt.executed_at_utc)}",
                classes="kv",
            )
            with VerticalScroll(id="remediation-preview-scroll"):
                yield RichLog(id="remediation-preview-log", markup=False, wrap=True)
            yield Label("sudo password (kept in memory only; blank if root / NOPASSWD)", classes="field-label")
            yield Input(
                placeholder="sudo password (optional)",
                password=True,
                id="rollback-sudo-password",
            )
            with Horizontal(id="remediation-modal-actions"):
                yield Button("Confirm Rollback", id="btn-confirm-rollback", variant="error")
                yield Button("Cancel", id="btn-cancel-rollback")

    def on_mount(self) -> None:
        log = self.query_one("#remediation-preview-log", RichLog)
        if self._receipt.rollback_argv:
            log.write("ROLLBACK COMMAND (shell=False):")
            log.write(f"  {_format_argv(self._receipt.rollback_argv)}")
        if self._receipt.backup_path:
            log.write(f"BACKUP SNAPSHOT: {self._receipt.backup_path}")
        if self._receipt.rollback_notes:
            log.write(f"NOTES: {self._receipt.rollback_notes}")
        self.query_one("#rollback-sudo-password", Input).focus()

    def _clear_password_input(self) -> None:
        inputs = self.query("#rollback-sudo-password")
        if inputs:
            inputs.first(Input).value = ""

    def _confirm(self) -> None:
        password: str | None = None
        try:
            raw = self.query_one("#rollback-sudo-password", Input).value
            password = raw if raw else None
        finally:
            self._clear_password_input()
        self.dismiss((True, password))

    def action_cancel(self) -> None:
        self._clear_password_input()
        self.dismiss((False, None))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-confirm-rollback":
            self._confirm()
        elif event.button.id == "btn-cancel-rollback":
            self.action_cancel()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._confirm()


class RejectReasonScreen(ModalScreen[tuple[bool, str]]):
    """Modal allowing the analyst to reject a proposed fix with an optional note."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, item: RemediationItemView) -> None:
        super().__init__()
        self._item = item

    def compose(self) -> ComposeResult:
        with Vertical(id="remediation-reject-box"):
            yield Label("REJECT RECOMMENDATION", classes="panel-title")
            yield Static(
                f"{escape(self._item.recommendation_id)}  {escape(self._item.title)}",
                classes="kv",
            )
            yield Label("reason (optional)", classes="field-label")
            yield Input(
                placeholder="e.g. false positive or scheduled maintenance",
                id="reject-reason",
            )
            with Horizontal(id="remediation-modal-actions"):
                yield Button("Reject", id="btn-confirm-reject", variant="error")
                yield Button("Cancel", id="btn-cancel-reject")

    def on_mount(self) -> None:
        self.query_one("#reject-reason", Input).focus()

    def _confirm(self) -> None:
        reason = self.query_one("#reject-reason", Input).value.strip()
        self.dismiss((True, reason))

    def action_cancel(self) -> None:
        self.dismiss((False, ""))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-confirm-reject":
            self._confirm()
        elif event.button.id == "btn-cancel-reject":
            self.action_cancel()

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._confirm()
