import shutil

from .rows import COLUMNS, NVD_URL

RESET = "\033[0m"
GREY = "\033[2m"
STATE_COLORS = {
    "draft":     "\033[36m",
    "triage":    "\033[33m",
    "published": "\033[32m",
    "closed":    GREY,
}
PULL_COLORS = {
    "open":   "\033[32m",
    "merged": "\033[35m",
    "closed": "\033[31m",
}
GAP = "  "  # column separator on a tty; plain mode uses a tab
RIGHT_ALIGNED = ("created", "updated", "to-publish")


def render(rows, columns=None, plain=False, term_width=None):
    """The table as (header, lines): one line per advisory, so `wc -l` counts advisories.

    With plain=True (used when stdout is not a tty) cells are tab separated with
    no colors, padding or truncation, so the output pipes into cut/awk/datamash.

    `columns` comes from select_columns(), so it is in COLUMNS order; PRs is
    therefore last, which is why its cell is the one left unpadded.
    """
    cols = COLUMNS if columns is None else columns
    if not cols:
        return "", []  # nothing to show: --columns and --redact ruled everything out
    if plain:
        lines = ["\t".join(cell_text(row, c, plain=True) for c in cols) for row in rows]
        return "\t".join(cols), lines

    widths = column_widths(rows, cols, term_width)
    cols = [c for c in cols if widths[c]]  # a column no advisory fills is dropped
    if not cols:
        return "", []
    header = GAP.join(c.ljust(widths[c]) for c in cols).rstrip()
    lines = [GAP.join(styled(row, c, widths[c]) for c in cols).rstrip() for row in rows]
    return GREY + header + RESET, lines


def cell_text(row, col, plain=False):
    """The undecorated text of one cell — also what its column width is measured from."""
    if col == "PRs" and row["PRs"]:
        return "PRs: " + row["PRs"]
    if col == "to-publish" and plain:
        return row["to-publish"] or "NA"  # so `datamash --narm` can skip unpublished rows
    return row[col]


def column_widths(rows, cols, term_width=None):
    """One width per column for the whole run, measured across every org.

    Measuring per org would size `repo` (and the rest) to that org's longest
    value and stagger the table; one set of widths keeps every advisory, and the
    header, in the same table. A column no row fills gets width 0, meaning "drop
    it"; the others are never narrower than their own name.
    """
    if not rows:
        return {c: len(c) for c in cols}

    widths = {}
    for col in cols:
        filled = max(len(cell_text(row, col)) for row in rows)
        widths[col] = max(filled, len(col)) if filled else 0
    if widths.get("title"):
        # title is elastic: it gets whatever the other columns leave behind
        term_width = term_width or shutil.get_terminal_size(fallback=(120, 24)).columns
        used = sum(w + len(GAP) for c, w in widths.items() if c != "title" and w)
        widths["title"] = max(10, term_width - used)
    return widths


def styled(row, col, width):
    """One tty cell: colored or linked, then padded to `width` visible characters."""
    # padding is kept out of `text` so that colors and links wrap the visible
    # characters only, and the trailing spaces of the last cell still rstrip
    text = cell_text(row, col)[:width]
    pad = " " * (width - len(text))
    if col in RIGHT_ALIGNED:
        text, pad = pad + text, ""
    if col in ("created", "updated"):
        return age_badge(row[col + "_age"], text)
    if col == "state":
        return STATE_COLORS.get(row["state"], "") + text + pad + RESET
    if col in ("ghsa", "title") and text and row["url"]:
        return link(text, row["url"]) + pad
    if col == "cve" and text:
        return link(text, NVD_URL.format(text)) + pad
    if col == "PRs" and row["pulls"]:
        labels = [PULL_COLORS.get(p["state"], GREY) + link(p["label"], p["url"]) + RESET
                  for p in row["pulls"]]
        return "PRs: " + ", ".join(labels)
    return text + pad


def link(text, url):
    """An underlined OSC 8 hyperlink; terminals without support just show the text."""
    return f"\033[4m\033]8;;{url}\033\\{text}\033]8;;\033\\\033[24m"


def age_badge(days, text):
    """`text` on a plasma background: blue when it happened long ago, yellow when recent."""
    freshness = 0.0 if days is None else max(0.0, 1 - days / 365)
    red = int(13 + 240 * freshness)
    green = int(8 + 223 * freshness)
    blue = int(135 - 98 * freshness)
    ink = "\033[30m" if 0.299 * red + 0.587 * green + 0.114 * blue > 128 else "\033[97m"
    return f"\033[48;2;{red};{green};{blue}m{ink}{text}{RESET}"
