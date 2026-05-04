from .constants import BOLD, GREY, RESET, PR_STATE_COLORS, STATE_COLORS
from .render_common import age_t, days_ago, group_by_repo, plasma_rgb, pr_state


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


def render_org(org, states, results_by_key, pull_results=None, redact=False):
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    lines = [f"\n{BOLD}=== {org if not redact else 'REDACTED ORG'} ==={RESET}"]

    if not advisories:
        if not redact:
            lines.append("  (no advisories)")
        return "\n".join(lines)

    for repo, items in group_by_repo(advisories):
        items = sorted(items, key=lambda a: a.get("updated_at", ""), reverse=True)
        lines.append(f"{BOLD}{repo if not redact else 'REDACTED REPO'}{RESET}")
        for advisory in items:
            id_ = advisory.get("ghsa_id", "") if not redact else "GHSA-xxxx-yyyy-zzzz"
            url = advisory.get("html_url", "")
            date = advisory.get("updated_at", "")
            title = (advisory.get("summary") or "")[:40].ljust(40)
            state_val = advisory.get("state") or "?"
            state_str = _color(state_val.ljust(9), STATE_COLORS.get(state_val, ""))
            cve = advisory.get("cve_id") or ""
            cve_str = _color(cve[:15].ljust(15), GREY)
            fork = advisory.get("private_fork")
            fork_html_url = fork.get("html_url") if fork else None
            first_pull = (pull_results or {}).get(fork_html_url) if fork_html_url else None
            ps = pr_state(first_pull)
            pull_str = (
                _color(_link("PR " + ps.ljust(6), first_pull["html_url"]), PR_STATE_COLORS.get(ps, GREY))
                if first_pull else " " * 9
            )
            d = days_ago(date)
            badge = _age_badge(date, (str(d) + "d").rjust(5))
            if redact:
                lines.append(f" {badge}\t{id_}  {state_str}")
            else:
                lines.append(f" {badge}\t{state_str}  {_color(_link(id_, url), GREY)}  {title}  {cve_str}  {pull_str}")

    return "\n".join(lines)
