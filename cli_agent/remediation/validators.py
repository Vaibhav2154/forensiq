"""Strict anti-prompt-injection parameter validators for local remediation playbooks."""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
from typing import Iterable


USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
OCTAL_MODE_RE = re.compile(r"^0?[0-7]{3}$")
CRON_FILE_RE = re.compile(r"^/etc/cron\.d/[A-Za-z0-9._-]+$")
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,63}$")

PROTECTED_USERNAMES = frozenset({"root", "daemon", "bin", "sys", "sync", "nobody"})

ALLOWLISTED_CRITICAL_PATHS = frozenset(
    {
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
    }
)

ALLOWLISTED_SSHD_DIRECTIVES: dict[str, tuple[str, ...]] = {
    "PermitRootLogin": ("no", "prohibit-password"),
    "PasswordAuthentication": ("no", "yes"),
    "PubkeyAuthentication": ("yes", "no"),
    "MaxAuthTries": ("1", "2", "3", "4", "5", "6"),
}

_FORBIDDEN_CHARS_RE = re.compile(r"[;|&$`<>\\\n\r\t]")


def _reject_shell_metachars(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if _FORBIDDEN_CHARS_RE.search(value):
        raise ValueError(f"{field_name} contains forbidden shell characters")
    return value.strip()


def current_login_username() -> str:
    """Safely return the current local analyst username across Linux/macOS/Windows."""
    try:
        return os.getlogin()
    except OSError:
        return getpass.getuser()


def validate_username(username: str, *, current_user: str | None = None) -> str:
    """Validate a POSIX local username; refuses root and the current analyst account."""
    cleaned = _reject_shell_metachars(username, "username")
    if not USERNAME_RE.match(cleaned):
        raise ValueError(
            f"invalid username {cleaned!r}: must match {USERNAME_RE.pattern}"
        )
    if cleaned in PROTECTED_USERNAMES:
        raise ValueError(f"refusing to target protected system account {cleaned!r}")
    active_user = (current_user if current_user is not None else current_login_username()).strip()
    if active_user and cleaned == active_user:
        raise ValueError(
            f"refusing to lock or terminate current analyst account {cleaned!r}"
        )
    return cleaned


def validate_ip(ip: str, *, blocked_ips: Iterable[str] = ()) -> str:
    """Validate an IPv4/IPv6 address; refuses loopback, link-local, and backend server IPs."""
    cleaned = _reject_shell_metachars(ip, "ip")
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid IP address {cleaned!r}") from exc

    if addr.is_loopback:
        raise ValueError(f"refusing to block loopback address {cleaned!r}")
    if addr.is_link_local:
        raise ValueError(f"refusing to block link-local address {cleaned!r}")
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError(f"refusing to block unspecified/multicast address {cleaned!r}")

    blocked_normalized = set()
    for raw_b in blocked_ips:
        try:
            blocked_normalized.add(str(ipaddress.ip_address(raw_b.strip())))
        except ValueError:
            continue
    if str(addr) in blocked_normalized:
        raise ValueError(f"refusing to block protected backend/control IP {str(addr)!r}")
    return str(addr)


def validate_pid(pid: str | int, *, protected_pids: Iterable[int] = ()) -> str:
    """Validate a target process ID; refuses PID <= 1 and current/parent TUI PIDs."""
    raw = str(pid).strip()
    if not raw.isdigit():
        raise ValueError(f"pid must be a positive integer, got {pid!r}")
    value = int(raw)
    if value <= 1:
        raise ValueError(f"refusing to kill protected PID {value}")
    protected = {os.getpid(), os.getppid(), *(int(p) for p in protected_pids)}
    if value in protected:
        raise ValueError(f"refusing to kill current or protected PID {value}")
    return str(value)


def validate_file_permission_params(path: str, mode: str) -> tuple[str, str]:
    """Validate an allowlisted critical system path and non-world-writable octal mode."""
    cleaned_path = _reject_shell_metachars(path, "path")
    if ".." in cleaned_path or cleaned_path not in ALLOWLISTED_CRITICAL_PATHS:
        raise ValueError(
            f"path {cleaned_path!r} is not in the allowlisted critical paths"
        )
    cleaned_mode = _reject_shell_metachars(mode, "mode")
    if not OCTAL_MODE_RE.match(cleaned_mode):
        raise ValueError(f"invalid octal mode {cleaned_mode!r}")
    normalized_mode = cleaned_mode.zfill(4)
    numeric = int(normalized_mode, 8)
    if numeric & 0o002:
        raise ValueError(f"refusing world-writable file mode {normalized_mode!r}")
    return cleaned_path, normalized_mode


def validate_sshd_params(directive: str, value: str) -> tuple[str, str]:
    """Validate an allowlisted sshd_config directive and safe value."""
    cleaned_dir = _reject_shell_metachars(directive, "directive")
    cleaned_val = _reject_shell_metachars(value, "value")
    allowed = ALLOWLISTED_SSHD_DIRECTIVES.get(cleaned_dir)
    if allowed is None:
        raise ValueError(
            f"sshd directive {cleaned_dir!r} is not allowlisted "
            f"(allowed: {sorted(ALLOWLISTED_SSHD_DIRECTIVES)})"
        )
    if cleaned_val not in allowed:
        raise ValueError(
            f"value {cleaned_val!r} is not permitted for {cleaned_dir} (allowed: {allowed})"
        )
    return cleaned_dir, cleaned_val


def validate_cron_file_path(path: str) -> str:
    """Validate a cron job file path strictly inside ``/etc/cron.d/``."""
    cleaned = _reject_shell_metachars(path, "path")
    if ".." in cleaned or not CRON_FILE_RE.match(cleaned):
        raise ValueError(
            f"cron path {cleaned!r} must be a direct child file under /etc/cron.d/"
        )
    return cleaned


def validate_package_name(package: str) -> str:
    """Validate an OS package name for Tier-2 package patching."""
    cleaned = _reject_shell_metachars(package, "package")
    if not PACKAGE_NAME_RE.match(cleaned):
        raise ValueError(f"invalid package name {cleaned!r}")
    return cleaned
