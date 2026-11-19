"""Convenience entry point: ``python -m cli_agent.tui [--api-url URL]``."""

from __future__ import annotations

import argparse

from ..cli import _launch_tui


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cli_agent.tui")
    parser.add_argument(
        "--api-url",
        default=None,
        help="override the saved backend URL for this run",
    )
    args = parser.parse_args(argv)
    return _launch_tui(args.api_url)


if __name__ == "__main__":
    raise SystemExit(main())
