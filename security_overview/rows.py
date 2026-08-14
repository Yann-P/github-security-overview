from datetime import datetime, timezone

# Every column, in the order they are printed; --columns picks from these.
COLUMNS = ["created", "updated", "to-publish", "state", "org", "repo",
           "ghsa", "cve", "title", "PRs"]
# What survives --redact: ages and state, nothing that identifies the advisory.
PUBLIC_COLUMNS = ["created", "updated", "to-publish", "state", "org", "repo"]
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"


def select_columns(columns=None, redact=False):
    """The columns to print, always in COLUMNS order.

    `columns` is the --columns allow-list (None means all). Redaction is applied
    last, so it wins over anything the caller asked for.
    """
    chosen = COLUMNS if columns is None else [c for c in COLUMNS if c in columns]
    return [c for c in chosen if c in PUBLIC_COLUMNS] if redact else chosen


def moment(timestamp):
    """GitHub timestamps are ISO 8601 ending in Z; datetime wants +00:00."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def days_ago(timestamp):
    """Whole days between `timestamp` and now, or None if there is no timestamp."""
    if not timestamp:
        return None
    return (datetime.now(timezone.utc) - moment(timestamp)).days


def repo_name(advisory):
    """github.com/<org>/<repo>/security/advisories/... -> <repo>."""
    parts = (advisory.get("html_url") or "").split("/")
    return parts[4] if len(parts) > 4 else "unknown"


def pull_summary(pull):
    """What the PRs column shows for one pull request: `#12 (opened)` and where it points."""
    state = "merged" if pull.get("merged_at") else pull.get("state", "?")
    label = f"#{pull['number']} ({'opened' if state == 'open' else state})"
    return {"label": label, "url": pull.get("html_url", ""), "state": state}


def build_rows(advisories, orgs, redact=False):
    """One row per advisory, orgs in the order asked for and newest update first.

    A row holds the text of every column, ready to print, plus the few raw
    values a renderer decorates with: the advisory `url`, the `pulls` behind the
    PRs column, and `created_age`/`updated_age`, the day counts the terminal
    renderer colors the age badges by.
    """
    rows = []
    for org in orgs:
        mine = [a for a in advisories if a.get("org") == org]
        # ghsa_id breaks ties, or advisories updated in the same second would come
        # out in whichever order the concurrent fetches happened to finish in
        newest_first = sorted(mine, key=lambda a: (a.get("updated_at", ""), a.get("ghsa_id") or ""),
                              reverse=True)
        for advisory in newest_first:
            created, published = advisory.get("created_at"), advisory.get("published_at")
            is_published = advisory.get("state") == "published" and created and published
            to_publish = (moment(published) - moment(created)).days if is_published else ""
            pulls = [pull_summary(p) for p in advisory.get("pulls", [])]
            created_age, updated_age = days_ago(created), days_ago(advisory.get("updated_at"))
            rows.append({
                "created": "?" if created_age is None else str(created_age),
                "updated": "?" if updated_age is None else str(updated_age),
                "to-publish": str(to_publish),
                "state": advisory.get("state") or "?",
                "org": "REDACTED" if redact else org,
                "repo": "REDACTED" if redact else repo_name(advisory),
                "ghsa": advisory.get("ghsa_id") or "",
                "cve": advisory.get("cve_id") or "",
                "title": " ".join((advisory.get("summary") or "").split()),
                "PRs": ", ".join(p["label"] for p in pulls),
                "url": advisory.get("html_url", ""),
                "pulls": pulls,
                "created_age": created_age,
                "updated_age": updated_age,
            })
    return rows
