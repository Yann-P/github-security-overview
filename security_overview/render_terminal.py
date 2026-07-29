import shutil

from .constants import GREY, RESET, PR_STATE_COLORS, STATE_COLORS
from .render_common import (
    NVD_URL,
    age_t,
    days_ago,
    plasma_rgb,
    pr_label,
    pr_state,
    repo_name,
    select_columns,
    time_to_publish,
)

# columns whose cells are always the same width; the rest are measured from the data
_FIXED_WIDTHS = {"created": 4, "updated": 4, "state": 9}
_SEP = "  "  # column separator in tty mode; plain mode uses a tab


def _pulls_for(advisory, pull_results):
    fork = advisory.get("private_fork")
    fork_html_url = fork.get("html_url") if fork else None
    return (pull_results or {}).get(fork_html_url, []) if fork_html_url else []


def _pr_text(pulls):
    """The uncolored, unlinked PR cell — what it costs in columns."""
    return "PRs: " + ", ".join(pr_label(p) for p in pulls) if pulls else ""


def _visible(cols, widths):
    """Drop columns nothing fills (no CVE in the whole run, say), to save width."""
    return [c for c in cols if widths.get(c, 1) > 0]


def column_widths(states, results_by_key, pull_results=None, redact=False, columns=None, term_w=None):
    """Cell widths for one whole run, measured across *every* org.

    Measuring per org would stagger the table: each org would size `repo` (and
    the rest) to its own longest value, so lines from different orgs wouldn't
    line up. header() and render_org() share this one dict instead, which is
    also what lets the header sit over its column. A column measured at 0 stays
    0 so it can be collapsed; the others are never narrower than their name.
    """
    if term_w is None:
        term_w = shutil.get_terminal_size(fallback=(120, 24)).columns

    advisories, org_cols = [], []
    for (org, state), found in results_by_key.items():
        if state not in states or not found:
            continue
        org_cols.append("REDACTED" if redact else org)
        advisories.extend(found)
    if not advisories:
        return {}

    ttps = [time_to_publish(a) for a in advisories]
    widths = {
        **_FIXED_WIDTHS,
        "to-publish": max((len(str(t)) for t in ttps if t is not None), default=0),
        "org": max(len(o) for o in org_cols),
        "repo": max(len("REDACTED" if redact else repo_name(a)) for a in advisories),
        "ghsa": max(len(a.get("ghsa_id") or "") for a in advisories),
        "cve": max(len(a.get("cve_id") or "") for a in advisories),
        "PRs": max(len(_pr_text(_pulls_for(a, pull_results))) for a in advisories),
    }
    shown = _visible(select_columns(columns, redact), widths)
    widths = {c: max(w, len(c)) if w else 0 for c, w in widths.items()}
    # title is elastic: it gets whatever the fixed-width columns leave behind
    overhead = sum(widths[c] + len(_SEP) for c in shown if c in widths)
    widths["title"] = max(10, term_w - overhead)
    return widths


def header(redact=False, plain=False, columns=None, widths=None):
    """Column names for render_org lines; cli prints this to stderr."""
    cols = select_columns(columns, redact)
    if plain:
        return "\t".join(cols)
    widths = widths or {}
    line = _SEP.join(c.ljust(widths.get(c, len(c))) for c in _visible(cols, widths)).rstrip()
    return _color(line, GREY)


def _link(text, target):
    return f"\033[4m\033]8;;{target}\033\\{text}\033]8;;\033\\\033[24m"


def _color(text, c):
    return f"{c}{text}{RESET}"


def _age_badge(date_str, text):
    t = age_t(date_str) if date_str else 0.0
    r, g, b = plasma_rgb(t)
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    fg = "\033[30m" if luminance > 128 else "\033[97m"
    bg = f"\033[48;2;{r};{g};{b}m"
    return f"{bg}{fg}{text}{RESET}"


def _pad(text, visible_len, width):
    """Right-pad an already decorated cell, whose escapes don't take columns."""
    return text + " " * max(0, width - visible_len)


def render_org(org, states, results_by_key, pull_results=None, redact=False, plain=False,
               columns=None, widths=None):
    """One advisory per line (grep/wc -l friendly), headers on stderr only:

    created  updated  [to-publish]  state  org  repo  [ghsa]  [cve]  title  [PRs]

    `widths` comes from column_widths() over the whole run; when it isn't passed
    it is computed here from results_by_key, which holds every org either way,
    so orgs rendered one call at a time still share one set of columns.

    With plain=True (used when stdout is not a tty), cells are tab-separated
    with no ANSI codes, padding, or truncation, so output pipes cleanly into
    cut/awk/datamash.
    """
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    if not advisories:
        return ""

    advisories = sorted(advisories, key=lambda a: a.get("updated_at", ""), reverse=True)
    cols = select_columns(columns, redact)
    if not cols:
        return ""

    if plain:
        # every selected column emits, empty or not, so awk/cut field numbers hold
        sep, shown, widths = "\t", cols, {}
    else:
        if not widths:
            widths = column_widths(states, results_by_key, pull_results, redact, columns)
        sep, shown = _SEP, _visible(cols, widths)

    org_col = "REDACTED" if redact else org
    lines = []
    for advisory in advisories:
        url = advisory.get("html_url", "")
        created = advisory.get("created_at", "")
        updated = advisory.get("updated_at", "")
        state_val = advisory.get("state") or "?"
        ghsa = advisory.get("ghsa_id") or ""
        cve = advisory.get("cve_id") or ""
        repo_col = "REDACTED" if redact else repo_name(advisory)
        summary = advisory.get("summary") or ""
        # time-to-publish (published_at - created_at) only applies to published advisories
        ttp = time_to_publish(advisory)
        pulls = _pulls_for(advisory, pull_results)

        cell = {}
        if plain:
            cell["created"] = str(days_ago(created))
            cell["updated"] = str(days_ago(updated))
            # NA (not "") so datamash --narm can skip non-published rows
            cell["to-publish"] = "NA" if ttp is None else str(ttp)
            cell["state"] = state_val
            cell["org"] = org_col
            cell["repo"] = repo_col
            cell["ghsa"] = ghsa
            cell["cve"] = cve
            cell["title"] = summary.replace("\t", " ")
            cell["PRs"] = _pr_text(pulls)
        else:
            cell["created"] = _age_badge(created, str(days_ago(created)).rjust(widths["created"]))
            cell["updated"] = _age_badge(updated, str(days_ago(updated)).rjust(widths["updated"]))
            cell["to-publish"] = ("" if ttp is None else str(ttp)).rjust(widths["to-publish"])
            cell["state"] = _color(state_val.ljust(widths["state"]), STATE_COLORS.get(state_val, ""))
            cell["org"] = org_col.ljust(widths["org"])
            cell["repo"] = repo_col.ljust(widths["repo"])
            ghsa_cell = _link(ghsa, url) if (ghsa and url) else ghsa
            cell["ghsa"] = _pad(ghsa_cell, len(ghsa), widths["ghsa"])
            cve_cell = _link(cve, NVD_URL.format(cve)) if cve else ""
            cell["cve"] = _pad(cve_cell, len(cve), widths["cve"])
            title = summary[:widths["title"]]
            cell["title"] = _pad(_link(title, url), len(title), widths["title"])
            cell["PRs"] = ("PRs: " + ", ".join(
                _color(_link(pr_label(p), p["html_url"]), PR_STATE_COLORS.get(pr_state(p), GREY))
                for p in pulls
            )) if pulls else ""

        lines.append(sep.join(cell[c] for c in shown).rstrip())

    return "\n".join(lines)
