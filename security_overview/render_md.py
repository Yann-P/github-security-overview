from .render_common import days_ago, group_by_repo


def render_org(org, states, results_by_key, pull_results=None, redact=False):
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    lines = [f"\n## {'REDACTED ORG' if redact else org}"]

    if not advisories:
        return ""

    for repo, items in group_by_repo(advisories):
        items = sorted(items, key=lambda a: a.get("updated_at", ""), reverse=True)
        lines.append(f"\n### {'REDACTED REPO' if redact else repo}\n")
        lines.append("| Age | State | Advisory | Title | CVE | PRs |")
        lines.append("|-----|-------|----------|-------|-----|-----|")
        for advisory in items:
            ghsa_id = advisory.get("ghsa_id", "") if not redact else "GHSA-xxxx-yyyy-zzzz"
            url = advisory.get("html_url", "")
            date = advisory.get("updated_at", "")
            title = (advisory.get("summary") or "")[:60]
            state_val = advisory.get("state") or "?"
            cve = advisory.get("cve_id") or ""
            fork = advisory.get("private_fork")
            fork_html_url = fork.get("html_url") if fork else None
            pulls = (pull_results or {}).get(fork_html_url, []) if fork_html_url else []
            d = days_ago(date)
            advisory_cell = f"[{ghsa_id}]({url})" if (url and not redact) else ghsa_id
            pr_cell = "PRs: " + ", ".join(f"[#{p['number']}]({p['html_url']})" for p in pulls) if pulls else ""
            lines.append(f"| {d}d | {state_val} | {advisory_cell} | {title} | {cve} | {pr_cell} |")

    return "\n".join(lines)
