import shutil

from .constants import BOLD, GREY, RESET, PR_STATE_COLORS, STATE_COLORS
from .render_common import age_t, days_ago, group_by_repo, plasma_rgb, pr_state

# Visible chars on the advisory line excluding title:
#   4(connector) + 3(badge) + 2 + 9(state) + 2 = 20
_FIXED_OVERHEAD = 20
_NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"


def _link(text, target):
    return f"\033[4m\033]8;;{target}\033\\{text}\033]8;;\033\\\033[24m"


def _color(text, c):
    return f"{c}{text}{RESET}"


def _dim(text):
    return _color(text, GREY)


def _fmt_age(days):
    if days < 7:
        s = f"{days}d"
    elif days < 30:
        s = f"{days // 7}w"
    elif days < 365:
        s = f"{days // 30}m"
    else:
        s = f"{days // 365}y"
    return s.rjust(3)


def _age_badge(date_str, text):
    t = age_t(date_str) if date_str else 0.0
    r, g, b = plasma_rgb(t)
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    fg = "\033[30m" if luminance > 128 else "\033[97m"
    bg = f"\033[48;2;{r};{g};{b}m"
    return f"{bg}{fg}{text}{RESET}"


def render_org(org, states, results_by_key, pull_results=None, redact=False):
    term_w = shutil.get_terminal_size(fallback=(120, 24)).columns
    title_w = max(10, term_w - _FIXED_OVERHEAD)
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    lines = [f"\n{BOLD}=== {org if not redact else 'REDACTED ORG'} ==={RESET}"]

    if not advisories:
        return ""

    first_repo = True
    for repo, items in group_by_repo(advisories):
        items = sorted(items, key=lambda a: a.get("updated_at", ""), reverse=True)
        if not items:
            continue
        if not first_repo:
            lines.append("")
        first_repo = False

        lines.append(f"{BOLD}{repo if not redact else 'REDACTED REPO'}{RESET}")
        for i, advisory in enumerate(items):
            is_last = i == len(items) - 1
            connector = _dim("└── " if is_last else "├── ")
            # prefix for sub-lines: continue the vertical bar only if more advisories follow
            sub_prefix = "    " if is_last else "│   "

            url = advisory.get("html_url", "")
            date = advisory.get("updated_at", "")
            state_val = advisory.get("state") or "?"
            state_str = _color(state_val.ljust(9), STATE_COLORS.get(state_val, ""))
            cve = advisory.get("cve_id") or ""
            fork = advisory.get("private_fork")
            fork_html_url = fork.get("html_url") if fork else None
            pulls = (pull_results or {}).get(fork_html_url, []) if fork_html_url else []
            title = (advisory.get("summary") or "")[:title_w]
            d = days_ago(date)
            badge = _age_badge(date, _fmt_age(d))

            if redact:
                lines.append(f"{connector}{badge}  {state_str}")
            else:
                lines.append(f"{connector}{badge}  {state_str}  {_link(title, url)}")

                sub_items = []
                if cve:
                    sub_items.append(_link(cve, _NVD_URL.format(cve)))
                if pulls:
                    pr_items = []
                    for p in pulls:
                        ps = pr_state(p)
                        label = "opened" if ps == "open" else ps
                        pr_items.append(_color(_link(f"#{p['number']} ({label})", p["html_url"]), PR_STATE_COLORS.get(ps, GREY)))
                    sub_items.append("PRs: " + ", ".join(pr_items))

                for j, sub_item in enumerate(sub_items):
                    is_last_sub = j == len(sub_items) - 1
                    sub_connector = _dim(sub_prefix + ("└── " if is_last_sub else "├── "))
                    lines.append(f"{sub_connector}{sub_item}")

    return "\n".join(lines)
