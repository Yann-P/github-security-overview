from .rows import COLUMNS, NVD_URL


def render(rows, columns=None):
    """Markdown: a `##` heading per org, a `###` heading and a table per repo."""
    # org and repo are headings here, so they never appear as columns
    cols = [c for c in (COLUMNS if columns is None else columns) if c not in ("org", "repo")]
    if not rows or not cols:
        return ""

    # rows arrive newest first, so first-seen order lists the freshest repo first
    by_repo = {}
    for row in rows:
        by_repo.setdefault((row["org"], row["repo"]), []).append(row)

    header = "| " + " | ".join(cols) + " |"
    divider = "|" + "|".join("-" * (len(c) + 2) for c in cols) + "|"
    lines, current_org = [], None
    for (org, repo), group in by_repo.items():
        if org != current_org:
            current_org = org
            lines.append(f"\n## {org}")
        lines += [f"\n### {repo}\n", header, divider]
        for row in group:
            lines.append("| " + " | ".join(cell(row, c) for c in cols) + " |")
    return "\n".join(lines)


def cell(row, col):
    """One table cell, linked where there is somewhere to point."""
    if col == "ghsa" and row["ghsa"] and row["url"]:
        return f"[{row['ghsa']}]({row['url']})"
    if col == "cve" and row["cve"]:
        return f"[{row['cve']}]({NVD_URL.format(row['cve'])})"
    if col == "PRs":
        return ", ".join(f"[{p['label']}]({p['url']})" for p in row["pulls"])
    return row[col].replace("|", r"\|")  # a bare pipe would break out of the cell
