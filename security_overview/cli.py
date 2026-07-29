import argparse
import os
import sys
from datetime import date

import httpx
import trio

from . import render_md, render_terminal
from .constants import ALL_STATES
from .fetch import check_token, fetch, fetch_pulls
from .render_common import HEADER_COLS

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


def parse_columns(value):
    cols = [c.strip() for c in value.split(",") if c.strip()]
    for c in cols:
        if c not in HEADER_COLS:
            raise argparse.ArgumentTypeError(
                f"invalid column {c!r} (choose from {', '.join(HEADER_COLS)})"
            )
    return cols


def parse_date(value):
    try:
        date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date {value!r} (expected YYYY-MM-DD)")
    return value


def filter_date_range(results, field, date_from, date_to):
    """Keep advisories whose `field` date falls in [date_from, date_to] (inclusive).

    Advisories missing the field (e.g. never published) are dropped when a bound is set.
    """
    if not date_from and not date_to:
        return results

    def keep(advisory):
        value = (advisory.get(field) or "")[:10]
        if not value:
            return False
        if date_from and value < date_from:
            return False
        if date_to and value > date_to:
            return False
        return True

    return {key: [a for a in advisories if keep(a)] for key, advisories in results.items()}


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
        "--columns",
        type=parse_columns,
        action="append",
        metavar="COL[,COL...]",
        help=(
            "show only these columns; repeatable and/or comma-separated, always "
            f"printed in the canonical order (default: all of {', '.join(HEADER_COLS)})"
        ),
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
    parser.add_argument(
        "--opened-from",
        type=parse_date,
        metavar="YYYY-MM-DD",
        help="only advisories opened on or after this date",
    )
    parser.add_argument(
        "--opened-to",
        type=parse_date,
        metavar="YYYY-MM-DD",
        help="only advisories opened on or before this date",
    )
    parser.add_argument(
        "--published-from",
        type=parse_date,
        metavar="YYYY-MM-DD",
        help="only advisories published on or after this date",
    )
    parser.add_argument(
        "--published-to",
        type=parse_date,
        metavar="YYYY-MM-DD",
        help="only advisories published on or before this date",
    )
    args = parser.parse_args()
    states = [s for group in (args.state or []) for s in group] or ALL_STATES
    columns = [c for group in (args.columns or []) for c in group] or None
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

        results = filter_date_range(results, "created_at", args.opened_from, args.opened_to)
        results = filter_date_range(results, "published_at", args.published_from, args.published_to)

        fork_urls = {
            advisory["private_fork"]["html_url"]
            for advisories in results.values()
            for advisory in advisories
            if advisory.get("private_fork") and advisory["private_fork"].get("html_url")
        }
        async with trio.open_nursery() as nursery:
            for fork_url in fork_urls:
                nursery.start_soon(fetch_pulls, client, fork_url, pull_results)

    render_kwargs = {"pull_results": pull_results, "redact": args.redact, "columns": columns}
    if args.format == "terminal":
        # tab-separated plain output when piped, so cut/awk/datamash can parse it
        plain = not sys.stdout.isatty()
        render_kwargs["plain"] = plain
        # one width per column for the whole run: every org and the header line
        # up in a single table, instead of each org sizing its own columns
        widths = None if plain else render_terminal.column_widths(
            states, results, pull_results, args.redact, columns
        )
        render_kwargs["widths"] = widths
        # headers go to stderr so stdout stays 1 line = 1 advisory
        print(
            render_terminal.header(redact=args.redact, plain=plain, columns=columns, widths=widths),
            file=sys.stderr,
        )
    for org in args.orgs:
        out = renderer.render_org(org, states, results, **render_kwargs)
        if out:
            print(out)
    # terminal format stays 1 line = 1 advisory so `wc -l` counts vulns
    if args.format == "md":
        print()


def run():
    """Synchronous console-script entry point."""
    try:
        trio.run(main)
    except BrokenPipeError:
        # downstream closed the pipe (e.g. `| head`); redirect stdout to
        # devnull so the interpreter's exit flush doesn't error too
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)  # 128 + SIGPIPE
