import argparse
import os
import sys
from datetime import date

import trio

from . import render_md, render_terminal
from .fetch import STATES, fetch_advisories, fetch_pulls, github_client
from .rows import COLUMNS, build_rows, select_columns


def name_list(valid, what):
    """An argparse type for `--flag a,b`: a comma-separated list of known names."""
    def parse(value):
        names = [v.strip() for v in value.split(",") if v.strip()]
        for name in names:
            if name not in valid:
                raise argparse.ArgumentTypeError(
                    f"invalid {what} {name!r} (choose from {', '.join(valid)})"
                )
        return names
    return parse


def parse_date(value):
    try:
        date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date {value!r} (expected YYYY-MM-DD)")
    return value


def in_date_range(timestamp, start, end):
    """Does this timestamp's day fall in [start, end]? A missing timestamp never does."""
    day = (timestamp or "")[:10]
    return bool(day) and (start is None or day >= start) and (end is None or day <= end)


def parse_args():
    parser = argparse.ArgumentParser(prog="security-overview")
    parser.add_argument("orgs", nargs="+", metavar="org")
    parser.add_argument(
        "--state",
        type=name_list(STATES, "state"),
        action="append",
        metavar="STATE[,STATE...]",
        help="filter by state; repeatable and/or comma-separated (default: all states)",
    )
    parser.add_argument(
        "--columns",
        type=name_list(COLUMNS, "column"),
        action="append",
        metavar="COL[,COL...]",
        help=(
            "show only these columns; repeatable and/or comma-separated, always "
            f"printed in the canonical order (default: all of {', '.join(COLUMNS)})"
        ),
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="hide org/repo names and drop every column that identifies an advisory",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "md"],
        default="terminal",
        help="output format (default: terminal)",
    )
    for when in ("opened", "published"):
        parser.add_argument(
            f"--{when}-from", type=parse_date, metavar="YYYY-MM-DD",
            help=f"only advisories {when} on or after this date",
        )
        parser.add_argument(
            f"--{when}-to", type=parse_date, metavar="YYYY-MM-DD",
            help=f"only advisories {when} on or before this date",
        )
    return parser.parse_args()


async def main():
    args = parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("error: GITHUB_TOKEN environment variable not set")

    # --state and --columns are repeatable, so each one holds a list of lists of names
    states = [s for group in args.state or [] for s in group] or STATES
    asked_for = [c for group in args.columns or [] for c in group]
    columns = select_columns(asked_for or None, args.redact)
    date_filters = [
        ("created_at", args.opened_from, args.opened_to),
        ("published_at", args.published_from, args.published_to),
    ]

    async with github_client(token) as client:
        advisories = await fetch_advisories(client, args.orgs, states)
        for field, start, end in date_filters:
            if start or end:
                advisories = [a for a in advisories if in_date_range(a.get(field), start, end)]
        # after filtering, so we only ask about the forks we are going to print
        await fetch_pulls(client, advisories)

    rows = build_rows(advisories, args.orgs, args.redact)
    if args.format == "md":
        markdown = render_md.render(rows, columns)
        if markdown:
            print(markdown + "\n")
        return

    header, lines = render_terminal.render(rows, columns, plain=not sys.stdout.isatty())
    print(header, file=sys.stderr)  # headers go to stderr so stdout stays 1 line = 1 advisory
    for line in lines:
        print(line)


def run():
    """Synchronous console-script entry point."""
    try:
        trio.run(main)
    except BrokenPipeError:
        # downstream closed the pipe (e.g. `| head`); point stdout at devnull so
        # the interpreter's exit flush doesn't fail too
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)  # 128 + SIGPIPE
