from .render_common import (
    HEADER_COLS,
    NVD_URL,
    days_ago,
    group_by_repo,
    pr_label,
    time_to_publish,
)

# org/repo are headings in markdown, so they drop out of the table itself
_COLS = [c for c in HEADER_COLS if c not in ("org", "repo")]
# redaction strips advisory-identifying columns, same as the terminal renderer
_REDACTED_COLS = _COLS[: _COLS.index("state") + 1]


def _cell(text):
    """Escape what would otherwise break out of a table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_org(org, states, results_by_key, pull_results=None, redact=False):
    advisories = []
    for state in states:
        advisories.extend(results_by_key.get((org, state), []))

    if not advisories:
        return ""

    cols = _REDACTED_COLS if redact else _COLS
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
            cells = [
                days_ago(advisory.get("created_at", "")),
                days_ago(advisory.get("updated_at", "")),
                "" if ttp is None else ttp,
                advisory.get("state") or "?",
            ]

            if not redact:
                url = advisory.get("html_url", "")
                ghsa_id = advisory.get("ghsa_id") or ""
                cve = advisory.get("cve_id") or ""
                fork = advisory.get("private_fork")
                fork_html_url = fork.get("html_url") if fork else None
                pulls = (pull_results or {}).get(fork_html_url, []) if fork_html_url else []
                cells += [
                    f"[{ghsa_id}]({url})" if (ghsa_id and url) else ghsa_id,
                    f"[{cve}]({NVD_URL.format(cve)})" if cve else "",
                    _cell(advisory.get("summary") or ""),
                    ", ".join(f"[{pr_label(p)}]({p['html_url']})" for p in pulls),
                ]

            lines.append("| " + " | ".join(str(c) for c in cells) + " |")

    return "\n".join(lines)
