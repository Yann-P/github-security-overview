from datetime import datetime, timezone


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


def days_ago(date_str):
    if not date_str:
        return "?"
    return (
        datetime.now(timezone.utc)
        - datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    ).days


def group_by_repo(advisories):
    by_repo = {}
    for advisory in advisories:
        repo = (advisory.get("html_url") or "").split("/")[4] or "unknown"
        by_repo.setdefault(repo, []).append(advisory)
    return sorted(
        by_repo.items(),
        key=lambda x: max(a.get("updated_at", "") for a in x[1]),
        reverse=True,
    )
