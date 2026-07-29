from .render_common import (
    NVD_URL,
    days_ago,
    group_by_repo,
    pr_label,
    select_columns,
    time_to_publish,
)


def _cell(text):
    """Escape what would otherwise break out of a table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_org(org, states, results_by_key, pull_results=None, redact=False, columns=None):
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    if not advisories:
        return ""

    # org/repo are headings in markdown, so they never appear as columns
    cols = [c for c in select_columns(columns, redact) if c not in ("org", "repo")]
    if not cols:
        return ""

    header = "| " + " | ".join(cols) + " |"
    divider = "|" + "|".join("-" * (len(c) + 2) for c in cols) + "|"

    lines = [f"\n## {'REDACTED ORG' if redact else org}"]

    for repo, items in group_by_repo(advisories):
        items = sorted(items, key=lambda a: a.get("updated_at", ""), reverse=True)
        lines.append(f"\n### {'REDACTED REPO' if redact else repo}\n")
        lines.append(header)
        lines.append(divider)
        for advisory in items:
            ttp = time_to_publish(advisory)
            url = advisory.get("html_url", "")
            ghsa_id = advisory.get("ghsa_id") or ""
            cve = advisory.get("cve_id") or ""
            fork = advisory.get("private_fork")
            fork_html_url = fork.get("html_url") if fork else None
            pulls = (pull_results or {}).get(fork_html_url, []) if fork_html_url else []
            cell = {
                "created": days_ago(advisory.get("created_at", "")),
                "updated": days_ago(advisory.get("updated_at", "")),
                "to-publish": "" if ttp is None else ttp,
                "state": advisory.get("state") or "?",
                "ghsa": f"[{ghsa_id}]({url})" if (ghsa_id and url) else ghsa_id,
                "cve": f"[{cve}]({NVD_URL.format(cve)})" if cve else "",
                "title": _cell(advisory.get("summary") or ""),
                "PRs": ", ".join(f"[{pr_label(p)}]({p['html_url']})" for p in pulls),
            }
            lines.append("| " + " | ".join(str(cell[c]) for c in cols) + " |")

    return "\n".join(lines)
