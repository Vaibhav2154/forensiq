"""Command-line front end for ForensIQ.

Thin presentation over :class:`cli_agent.services.CliService`. Argument names and
command shapes mirror the legacy LogIQ CLI so existing muscle memory keeps
working; nothing here implements authentication, collection or HTTP itself.

``forensiq tui`` is the only command that does not go through this module's
dispatch: the Textual application owns its own event loop and reuses
``CliService`` directly.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .services.cli_service import CliService
from .services.errors import ForensIQError
from .services.monitoring_service import MonitoringState

DEFAULT_API_URL = "http://localhost:8000"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensiq",
        description="ForensIQ CLI - authenticated system-log monitoring and analysis",
    )
    parser.add_argument("--version", action="version", version=f"forensiq {__version__}")
    sub = parser.add_subparsers(dest="command")

    auth = sub.add_parser("auth", help="authentication commands")
    auth_sub = auth.add_subparsers(dest="auth_command")
    login = auth_sub.add_parser("login", help="log in and store a session token")
    login.add_argument("--username", required=True)
    login.add_argument("--password", help="prompted when omitted")
    login.add_argument("--api-url", default=None, help=f"backend URL (default {DEFAULT_API_URL})")
    register = auth_sub.add_parser("register", help="register a new account")
    register.add_argument("--username", required=True)
    register.add_argument("--email", required=True)
    register.add_argument("--password", help="prompted when omitted")
    register.add_argument("--api-url", default=None)
    auth_sub.add_parser("profile", help="show the authenticated profile")
    auth_sub.add_parser("logout", help="forget the local session")

    profile = sub.add_parser("profile", help="monitoring profile commands")
    profile_sub = profile.add_subparsers(dest="profile_command")
    setup = profile_sub.add_parser("setup", help="configure file-based monitoring")
    setup.add_argument("--log-path", required=True)
    setup.add_argument("--interval", type=int, default=300)
    setup.add_argument("--max-results", type=int, default=5)
    setup.add_argument("--no-enhance", action="store_true")
    dynamic = profile_sub.add_parser("setup-dynamic", help="configure system-log monitoring")
    dynamic.add_argument("--sources", nargs="*")
    dynamic.add_argument("--interval", type=int, default=300)
    dynamic.add_argument("--max-results", type=int, default=5)
    dynamic.add_argument("--no-enhance", action="store_true")
    dynamic.add_argument("--list-sources", action="store_true")
    profile_sub.add_parser("status", help="show the stored profile")

    monitor = sub.add_parser("monitor", help="start monitoring")
    mode = monitor.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dynamic", action="store_true", help="collect from system log sources")
    mode.add_argument("--start", action="store_true", help="tail the configured log file")
    monitor.add_argument("--sources", nargs="*")
    monitor.add_argument("--interval", type=int)

    analyze = sub.add_parser("analyze", help="analyse a log file once")
    analyze.add_argument("--file", required=True)
    analyze.add_argument("--output", help="write the raw analysis JSON here")
    analyze.add_argument("--no-enhance", action="store_true")

    tui = sub.add_parser("tui", help="launch the terminal dashboard")
    tui.add_argument(
        "--api-url",
        default=None,
        help=f"backend URL for this run (defaults to the saved config, {DEFAULT_API_URL})",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "tui":
        return _launch_tui(args.api_url)
    try:
        return asyncio.run(_dispatch(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except ForensIQError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _launch_tui(api_url: str | None = None) -> int:
    """Run the Textual app; ``textual`` stays an optional dependency."""
    try:
        from .tui.app import ForensIQApp
    except ImportError:
        print(
            "error: the TUI requires the optional 'textual' dependency\n"
            "       install it with: pip install 'forensiq-cli[tui]'",
            file=sys.stderr,
        )
        return 1
    service = None
    if api_url:
        service = CliService()
        service.configure_monitoring(base_url=api_url.rstrip("/"))
    ForensIQApp(service=service).run()
    return 0


async def _dispatch(args: argparse.Namespace) -> int:
    service = CliService()
    try:
        if args.command == "auth":
            return await _handle_auth(service, args)
        if args.command == "profile":
            return _handle_profile(service, args)
        if args.command == "monitor":
            return await _handle_monitor(service, args)
        if args.command == "analyze":
            return await _handle_analyze(service, args)
        return 1
    finally:
        await service.close()


# -- auth ----------------------------------------------------------------
async def _handle_auth(service: CliService, args: argparse.Namespace) -> int:
    if args.auth_command == "login":
        password = args.password or getpass.getpass("password: ")
        session = await service.login(args.username, password, base_url=args.api_url)
        print(f"logged in as {session.username}")
        return 0
    if args.auth_command == "register":
        password = args.password or getpass.getpass("password: ")
        confirm = getpass.getpass("confirm password: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            return 1
        await service.register(args.username, args.email, password)
        print("registration successful; you can now log in")
        return 0
    if args.auth_command == "profile":
        if service.restore_session() is None:
            print("error: not logged in; run 'forensiq auth login'", file=sys.stderr)
            return 1
        profile = await service.profile()
        print(f"username: {profile.get('username')}")
        print(f"email:    {profile.get('email')}")
        return 0
    if args.auth_command == "logout":
        service.logout()
        print("logged out")
        return 0
    print("usage: forensiq auth {login|register|profile|logout}", file=sys.stderr)
    return 1


# -- profile -------------------------------------------------------------
def _handle_profile(service: CliService, args: argparse.Namespace) -> int:
    if args.profile_command == "setup":
        config = service.configure_monitoring(
            monitoring_type="file",
            log_path=str(Path(args.log_path).expanduser().resolve()),
            interval_seconds=args.interval,
            max_results=args.max_results,
            enhance_with_ai=not args.no_enhance,
        )
        print(f"configured file monitoring for {config.log_path} every {config.interval_seconds}s")
        return 0
    if args.profile_command == "setup-dynamic":
        if args.list_sources:
            for source in service.available_sources():
                print(f"{source.get('id')}: {source.get('description')} [{source.get('type')}]")
            return 0
        config = service.configure_monitoring(
            monitoring_type="dynamic",
            sources=tuple(args.sources or ()),
            interval_seconds=args.interval,
            max_results=args.max_results,
            enhance_with_ai=not args.no_enhance,
        )
        sources = ", ".join(config.sources) or "all available"
        print(f"configured dynamic monitoring ({sources}) every {config.interval_seconds}s")
        return 0
    if args.profile_command == "status":
        status = service.status()
        print(f"backend:   {status['base_url']}")
        print(f"logged in: {'yes' if status['authenticated'] else 'no'}")
        for key, value in status["config"].items():
            print(f"{key}: {value}")
        return 0
    print("usage: forensiq profile {setup|setup-dynamic|status}", file=sys.stderr)
    return 1


# -- monitor -------------------------------------------------------------
async def _handle_monitor(service: CliService, args: argparse.Namespace) -> int:
    if service.restore_session() is None:
        print("error: not logged in; run 'forensiq auth login'", file=sys.stderr)
        return 1
    service.configure_monitoring(
        monitoring_type="dynamic" if args.dynamic else "file",
        sources=tuple(args.sources or ()),
    )
    monitoring = await service.start_monitoring(
        interval=args.interval,
        on_state_change=lambda state: print(f"monitoring: {state.value}"),
        on_result=lambda view, outcome: print(
            f"cycle {outcome.cycle}: {outcome.collected_entries} entries, "
            f"{view.technique_count} technique(s)"
        ),
        on_error=lambda exc, _outcome: print(f"monitoring error: {exc}", file=sys.stderr),
    )
    print(f"monitoring started (interval {monitoring.interval_seconds}s); ctrl+c to stop")
    try:
        while monitoring.state is MonitoringState.RUNNING:
            await asyncio.sleep(0.5)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await service.stop_monitoring()
    return 0


# -- analyze -------------------------------------------------------------
async def _handle_analyze(service: CliService, args: argparse.Namespace) -> int:
    if service.restore_session() is None:
        print("error: not logged in; run 'forensiq auth login'", file=sys.stderr)
        return 1
    view = await service.analyze_file(args.file, enhance_with_ai=not args.no_enhance)
    print(view.summary or "(no summary returned)")
    for technique in view.techniques:
        score = "" if technique.relevance_score is None else f" score={technique.relevance_score:.2f}"
        print(f"  {technique.technique_id or '?'} {technique.name or ''}{score}")
    if view.threat_level is None:
        print("threat level: not reported by the backend")
    else:
        print(f"threat level: {view.threat_level}")
    if args.output:
        Path(args.output).write_text(json.dumps(dict(view.raw), indent=2, default=str), encoding="utf-8")
        print(f"raw response written to {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
