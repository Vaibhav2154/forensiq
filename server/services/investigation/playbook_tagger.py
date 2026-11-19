"""Deterministic post-processor mapping investigation recommendations to local TUI playbooks.

Prompt-injection immunity guarantee:
- Playbook IDs and parameters are derived strictly from verified ``NormalizedEvent``
  features and ``ObservedIOC`` records (never from arbitrary free-text shell snippets).
- Every extracted parameter is validated against strict allowlists / regexes before
  attaching ``fixable_via_tui=True``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Sequence

from contracts import NormalizedEvent
from services.investigation.models import (
    EventAnalysisOutput,
    FixTier,
    PlaybookId,
    RecommendationItem,
)


_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_CRON_PATH_RE = re.compile(r"^/etc/cron\.d/[A-Za-z0-9._-]+$")
_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,63}$")

_CRITICAL_FILE_DEFAULT_MODES: dict[str, str] = {
    "/etc/shadow": "0600",
    "/etc/gshadow": "0600",
    "/etc/passwd": "0644",
    "/etc/sudoers": "0440",
    "/etc/ssh/sshd_config": "0600",
}

_PROTECTED_USERS = frozenset({"root", "nobody", "daemon", "sync", "shutdown", "halt"})


def _is_valid_blockable_ip(value: str) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
        return None
    return str(ip_obj)


def _is_valid_target_user(value: str) -> str | None:
    cleaned = value.strip()
    if not cleaned or cleaned in _PROTECTED_USERS:
        return None
    if not _USERNAME_RE.match(cleaned):
        return None
    return cleaned


def _collect_verified_targets(
    events: Sequence[NormalizedEvent],
    event_analysis: EventAnalysisOutput | None = None,
) -> dict[str, list[str]]:
    """Extract verified candidate IPs, usernames, PIDs, file paths, and packages from evidence."""
    ips: list[str] = []
    users: list[str] = []
    pids: list[str] = []
    file_paths: list[str] = []
    cron_paths: list[str] = []
    packages: list[str] = []

    def _add(target_list: list[str], val: str | None) -> None:
        if val and val not in target_list:
            target_list.append(val)

    for evt in events:
        f = evt.features or {}
        if f.get("remote_ip"):
            _add(ips, _is_valid_blockable_ip(str(f["remote_ip"])))
        if f.get("account"):
            _add(users, _is_valid_target_user(str(f["account"])))
        if f.get("pid") is not None:
            try:
                pid_int = int(f["pid"])
                if pid_int > 1:
                    _add(pids, str(pid_int))
            except (TypeError, ValueError):
                pass
        cmd = str(f.get("command") or "")
        for critical_path in _CRITICAL_FILE_DEFAULT_MODES:
            if critical_path in cmd:
                _add(file_paths, critical_path)
        for token in cmd.split():
            if _CRON_PATH_RE.match(token):
                _add(cron_paths, token)
        if f.get("package"):
            pkg = str(f["package"]).strip().lower()
            if _PKG_RE.match(pkg):
                _add(packages, pkg)

    if event_analysis is not None:
        for ioc in event_analysis.iocs:
            val = ioc.value.strip()
            if ioc.ioc_type == "ip":
                _add(ips, _is_valid_blockable_ip(val))
            elif ioc.ioc_type == "account":
                _add(users, _is_valid_target_user(val))
            elif ioc.ioc_type == "file_path":
                if val in _CRITICAL_FILE_DEFAULT_MODES:
                    _add(file_paths, val)
                elif _CRON_PATH_RE.match(val):
                    _add(cron_paths, val)
            elif ioc.ioc_type == "command":
                for critical_path in _CRITICAL_FILE_DEFAULT_MODES:
                    if critical_path in val:
                        _add(file_paths, critical_path)

    return {
        "ips": ips,
        "users": users,
        "pids": pids,
        "file_paths": file_paths,
        "cron_paths": cron_paths,
        "packages": packages,
    }


def _find_mentioned(candidates: Iterable[str], haystack: str) -> str | None:
    lowered = haystack.lower()
    for item in candidates:
        if item.lower() in lowered:
            return item
    return None


def _classify_single_recommendation(
    rec: RecommendationItem,
    verified: dict[str, list[str]],
) -> tuple[bool, FixTier, PlaybookId, dict[str, str]]:
    """Deterministically match one recommendation to a Tier-1/2 playbook or Tier-3 advisory."""
    # If already explicitly tagged with a non-manual playbook whose params are valid, preserve it
    if rec.playbook_id != "manual_only" and rec.playbook_params:
        if rec.playbook_id == "block_ip" and _is_valid_blockable_ip(rec.playbook_params.get("ip", "")):
            return True, "tier_1_playbook", "block_ip", {"ip": _is_valid_blockable_ip(rec.playbook_params["ip"]) or ""}
        if rec.playbook_id in ("lock_user", "terminate_user_sessions") and _is_valid_target_user(rec.playbook_params.get("username", "")):
            return True, "tier_1_playbook", rec.playbook_id, {"username": rec.playbook_params["username"].strip()}
        if rec.playbook_id == "fix_file_permissions":
            path = rec.playbook_params.get("path", "").strip()
            mode = rec.playbook_params.get("mode", "").strip()
            if path in _CRITICAL_FILE_DEFAULT_MODES and re.match(r"^0?[46][04][04]$", mode):
                return True, "tier_1_playbook", "fix_file_permissions", {"path": path, "mode": mode}
        if rec.playbook_id == "harden_sshd_config":
            directive = rec.playbook_params.get("directive", "").strip()
            value = rec.playbook_params.get("value", "").strip()
            if directive in ("PermitRootLogin", "PasswordAuthentication", "MaxAuthTries", "PubkeyAuthentication") and value:
                return True, "tier_2_config_diff", "harden_sshd_config", {"directive": directive, "value": value}

    blob = f"{rec.title} {rec.target} {rec.action}".lower()

    # 1. Block external attacker IP (Tier 1)
    if any(kw in blob for kw in ("block", "deny", "firewall", "ufw", "iptables", "nft", "ban")):
        matched_ip = _find_mentioned(verified["ips"], blob) or (
            verified["ips"][0] if ("ip" in blob and verified["ips"]) else None
        )
        if matched_ip:
            return True, "tier_1_playbook", "block_ip", {"ip": matched_ip}

    # 2. Terminate active user sessions (Tier 1)
    if any(kw in blob for kw in ("terminate", "revoke session", "kill session", "pkill", "kick")):
        matched_user = _find_mentioned(verified["users"], blob) or (
            verified["users"][0] if ("account" in blob or "user" in blob) and verified["users"] else None
        )
        if matched_user:
            return True, "tier_1_playbook", "terminate_user_sessions", {"username": matched_user}

    # 3. Lock / disable compromised local account (Tier 1)
    if any(kw in blob for kw in ("lock", "disable account", "disable user", "suspend", "usermod")):
        matched_user = _find_mentioned(verified["users"], blob) or (
            verified["users"][0] if ("account" in blob or "user" in blob) and verified["users"] else None
        )
        if matched_user:
            return True, "tier_1_playbook", "lock_user", {"username": matched_user}

    # 4. Kill specific malicious process PID (Tier 1)
    if any(kw in blob for kw in ("kill process", "terminate process", "kill pid")) and verified["pids"]:
        matched_pid = _find_mentioned(verified["pids"], blob) or verified["pids"][0]
        return True, "tier_1_playbook", "kill_process", {"pid": matched_pid}

    # 5. Fix sensitive file permissions (Tier 1)
    if any(kw in blob for kw in ("chmod", "permission", "restrict access to /etc/", "harden /etc/shadow", "audit /etc/sudoers", "review sudoers")):
        matched_path = _find_mentioned(_CRITICAL_FILE_DEFAULT_MODES.keys(), blob) or (
            verified["file_paths"][0] if verified["file_paths"] and ("shadow" in blob or "sudoers" in blob) else None
        )
        if matched_path:
            return (
                True,
                "tier_1_playbook",
                "fix_file_permissions",
                {"path": matched_path, "mode": _CRITICAL_FILE_DEFAULT_MODES[matched_path]},
            )

    # 6. Harden SSHD configuration (Tier 2 Config Diff)
    if any(kw in blob for kw in ("sshd", "ssh configuration", "ssh config", "password authentication", "permitrootlogin", "key-based authentication")):
        if "permitrootlogin" in blob or "root login" in blob:
            return (
                True,
                "tier_2_config_diff",
                "harden_sshd_config",
                {"directive": "PermitRootLogin", "value": "no"},
            )
        if "maxauthtries" in blob or "lockout" in blob or "failed attempts" in blob:
            return (
                True,
                "tier_2_config_diff",
                "harden_sshd_config",
                {"directive": "MaxAuthTries", "value": "3"},
            )
        if "password authentication" in blob or "key-based" in blob or "harden ssh" in blob or "sshd_config" in blob:
            return (
                True,
                "tier_2_config_diff",
                "harden_sshd_config",
                {"directive": "PasswordAuthentication", "value": "no"},
            )

    # 7. Quarantine unauthorized cron file (Tier 2)
    if any(kw in blob for kw in ("cron", "/etc/cron.d/")) and verified["cron_paths"]:
        matched_cron = _find_mentioned(verified["cron_paths"], blob) or verified["cron_paths"][0]
        return True, "tier_2_config_diff", "quarantine_cron_file", {"path": matched_cron}

    # 8. Upgrade vulnerable package matched to CVE (Tier 2)
    if any(kw in blob for kw in ("upgrade package", "patch package", "update package", "apt ", "dnf ", "pacman ")) and verified["packages"]:
        matched_pkg = _find_mentioned(verified["packages"], blob) or verified["packages"][0]
        return True, "tier_2_config_diff", "upgrade_package", {"package": matched_pkg}

    # Default: Tier 3 Manual / Advisory Only
    return False, "tier_3_advisory", "manual_only", {}


def tag_recommendations_for_tui(
    recommendations: Sequence[RecommendationItem],
    events: Sequence[NormalizedEvent],
    event_analysis: EventAnalysisOutput | None = None,
) -> list[RecommendationItem]:
    """Attach deterministic HITL TUI playbook metadata to every RecommendationItem."""
    verified = _collect_verified_targets(events=events, event_analysis=event_analysis)
    tagged: list[RecommendationItem] = []

    for rec in recommendations:
        fixable, tier, playbook_id, params = _classify_single_recommendation(rec, verified)
        tagged.append(
            rec.model_copy(
                update={
                    "requires_human_approval": True,
                    "auto_executable": False,
                    "fixable_via_tui": fixable,
                    "fix_tier": tier,
                    "playbook_id": playbook_id,
                    "playbook_params": params,
                    "execution_status": rec.execution_status or "pending_approval",
                }
            )
        )

    return tagged
