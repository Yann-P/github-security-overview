import argparse

import httpx
import trio

from . import render_md, render_terminal
from .constants import ALL_STATES
from .fetch import check_token, fetch, fetch_pulls

RENDERERS = {
    "terminal": render_terminal,
    "md": render_md,
}


def parse_states(value):
    states = [s.strip() for s in value.split(",") if s.strip()]
    for s in states:
        if s not in ALL_STATES:
            raise argparse.ArgumentTypeError(
                f"invalid state {s!r} (choose from {', '.join(ALL_STATES)})"
            )
    return states


async def main():
    token = check_token()
    parser = argparse.ArgumentParser(prog="security-overview")
    parser.add_argument("orgs", nargs="+", metavar="org")
    parser.add_argument(
        "--state",
        type=parse_states,
        action="append",
        metavar="STATE[,STATE...]",
        help="filter by state; repeatable and/or comma-separated (default: all states)",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="hide org/repo names, GHSA random chars, and drop title + headers",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "md"],
        default="terminal",
        help="output format (default: terminal)",
    )
    args = parser.parse_args()
    states = [s for group in (args.state or []) for s in group] or ALL_STATES
    renderer = RENDERERS[args.format]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "security-overview",
    }

    results = {}
    pull_results = {}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        async with trio.open_nursery() as nursery:
            for org in args.orgs:
                for state in states:
                    nursery.start_soon(fetch, client, org, state, results)

        fork_urls = {
            advisory["private_fork"]["html_url"]
            for advisories in results.values()
            for advisory in advisories
            if advisory.get("private_fork") and advisory["private_fork"].get("html_url")
        }
        async with trio.open_nursery() as nursery:
            for fork_url in fork_urls:
                nursery.start_soon(fetch_pulls, client, fork_url, pull_results)

    for org in args.orgs:
        out = renderer.render_org(org, states, results, pull_results=pull_results, redact=args.redact)
        if out:
            print(out)
    print()


def run():
    """Synchronous console-script entry point."""
    trio.run(main)
