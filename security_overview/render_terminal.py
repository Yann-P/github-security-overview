import shutil

from .constants import GREY, RESET, PR_STATE_COLORS, STATE_COLORS
from .render_common import age_t, days_ago, days_between, plasma_rgb, pr_state, repo_name

# Visible chars per line excluding org/repo/cve/title/PRs:
#   4(created) + 2 + 4(updated) + 2 + 9(state) + 2 = 23
_FIXED_OVERHEAD = 23
_NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"

_HEADER_COLS = ["created", "updated", "to-publish", "state", "org", "repo", "cve", "title", "PRs"]


def header(redact=False, plain=False):
    """Column names for render_org lines; cli prints this to stderr."""
    cols = _HEADER_COLS[:6] if redact else _HEADER_COLS
    line = ("\t" if plain else "  ").join(cols)
    return line if plain else _color(line, GREY)


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


def render_org(org, states, results_by_key, pull_results=None, redact=False, plain=False):
    """One advisory per line (grep/wc -l friendly), headers on stderr only:

    created  updated  [to-publish]  state  org  repo  [cve]  title  [PRs]

    With plain=True (used when stdout is not a tty), cells are tab-separated
    with no ANSI codes, padding, or truncation, so output pipes cleanly into
    cut/awk/datamash.
    """
    term_w = shutil.get_terminal_size(fallback=(120, 24)).columns
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    if not advisories:
        return ""

    advisories = sorted(advisories, key=lambda a: a.get("updated_at", ""), reverse=True)

    # time-to-publish (published_at - created_at) only applies to published advisories
    ttps = [
        days_between(a.get("created_at"), a.get("published_at"))
        if a.get("state") == "published"
        else None
        for a in advisories
    ]
    ttp_w = max((len(str(t)) for t in ttps if t is not None), default=0)

    sep = "\t" if plain else "  "
    org_col = "REDACTED" if redact else org
    repo_w = max(len("REDACTED" if redact else repo_name(a)) for a in advisories)
    cve_w = 0 if redact else max(len(a.get("cve_id") or "") for a in advisories)
    # everything left of the title has fixed width
    base_overhead = (
        _FIXED_OVERHEAD + len(org_col) + 2 + repo_w + 2
        + (ttp_w + 2 if ttp_w else 0)
        + (cve_w + 2 if cve_w else 0)
    )

    lines = []
    for advisory, ttp in zip(advisories, ttps):
        url = advisory.get("html_url", "")
        created = advisory.get("created_at", "")
        updated = advisory.get("updated_at", "")
        state_val = advisory.get("state") or "?"
        repo_col = "REDACTED" if redact else repo_name(advisory)
        if plain:
            created_badge = str(days_ago(created))
            updated_badge = str(days_ago(updated))
            state_str = state_val
        else:
            created_badge = _age_badge(created, days_ago(created))
            updated_badge = _age_badge(updated, days_ago(updated))
            state_str = _color(state_val.ljust(9), STATE_COLORS.get(state_val, ""))
            repo_col = repo_col.ljust(repo_w)

        cells = [created_badge, updated_badge]
        if plain:
            # NA (not "") so datamash --narm can skip non-published rows
            cells.append("NA" if ttp is None else str(ttp))
        elif ttp_w:
            cells.append(("" if ttp is None else str(ttp)).rjust(ttp_w))
        cells += [state_str, org_col, repo_col]

        if redact:
            lines.append(sep.join(cells))
            continue

        if cve_w:
            cve = advisory.get("cve_id") or ""
            if plain:
                cells.append(cve)
            else:
                cve_cell = _link(cve, _NVD_URL.format(cve)) if cve else ""
                cells.append(cve_cell + " " * (cve_w - len(cve)))

        fork = advisory.get("private_fork")
        fork_html_url = fork.get("html_url") if fork else None
        pulls = (pull_results or {}).get(fork_html_url, []) if fork_html_url else []
        pr_cell = ""
        pr_len = 0
        if pulls:
            pr_items = []
            pr_texts = []
            for p in pulls:
                ps = pr_state(p)
                label = "opened" if ps == "open" else ps
                text = f"#{p['number']} ({label})"
                pr_texts.append(text)
                if plain:
                    pr_items.append(text)
                else:
                    pr_items.append(_color(_link(text, p["html_url"]), PR_STATE_COLORS.get(ps, GREY)))
            pr_cell = "PRs: " + ", ".join(pr_items)
            pr_len = len("PRs: " + ", ".join(pr_texts))

        if plain:
            cells.append((advisory.get("summary") or "").replace("\t", " "))
        else:
            title_w = max(10, term_w - base_overhead - (pr_len + 2 if pr_cell else 0))
            title = (advisory.get("summary") or "")[:title_w]
            cells.append(_link(title, url))
        if pr_cell:
            cells.append(pr_cell)

        lines.append(sep.join(cells).rstrip())

    return "\n".join(lines)
