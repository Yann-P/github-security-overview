from datetime import datetime, timezone

# Column set shared by the terminal and md renderers. The md renderer carries
# org/repo as headings instead of columns, but the rest line up 1:1.
HEADER_COLS = ["created", "updated", "to-publish", "state", "org", "repo", "ghsa", "cve", "title", "PRs"]
# what survives --redact: ages and state, nothing that identifies the advisory
REDACT_COLS = ["created", "updated", "to-publish", "state", "org", "repo"]
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"


def select_columns(columns=None, redact=False):
    """The columns to show, always in HEADER_COLS order.

    `columns` is the --columns allow-list (None means all). Redaction is applied
    last, so it wins over anything the caller asked for. Both renderers derive
    their header and their cells from this one list, which is what keeps the two
    in step and keeps rows matching the header.
    """
    cols = HEADER_COLS if columns is None else [c for c in HEADER_COLS if c in columns]
    if redact:
        cols = [c for c in cols if c in REDACT_COLS]
    return cols


def time_to_publish(advisory):
    """Days from creation to publication; None unless the advisory is published."""
    if advisory.get("state") != "published":
        return None
    return days_between(advisory.get("created_at"), advisory.get("published_at"))


def pr_label(pull):
    """`#12 (opened)` — the PR text both renderers show."""
    state = pr_state(pull)
    return f"#{pull['number']} ({'opened' if state == 'open' else state})"


def pr_state(pull):
    if pull is None:
        return None
    if pull.get("merged_at"):
        return "merged"
    return pull.get("state", "?")


def plasma_rgb(t):
    r = int(13 + (253 - 13) * t)
    g = int(8 + (231 - 8) * t)
    b = int(135 + (37 - 135) * t)
    return r, g, b


def age_t(date_str):
    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    age = (datetime.now(timezone.utc) - dt).days
    return max(0.0, 1.0 - age / 365)


def days_between(start_str, end_str):
    if not start_str or not end_str:
        return None
    start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
    end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    return (end - start).days


def days_ago(date_str):
    if not date_str:
        return "?"
    return (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    ).days


def repo_name(advisory):
    parts = (advisory.get("html_url") or "").split("/")
    return parts[4] if len(parts) > 4 else "unknown"


def group_by_repo(advisories):
    by_repo = {}
    for advisory in advisories:
        by_repo.setdefault(repo_name(advisory), []).append(advisory)
    return sorted(
        by_repo.items(),
        key=lambda x: max(a.get("updated_at", "") for a in x[1]),
        reverse=True,
    )
