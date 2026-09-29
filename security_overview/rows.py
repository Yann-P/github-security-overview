from datetime import datetime, timezone

# Every column, in the order they are printed; --columns picks from these.
COLUMNS = ["created", "updated", "to-publish", "state", "org", "repo",
           "ghsa", "cve", "title", "PRs"]
# What survives --redact: ages and state, nothing that identifies the advisory.
PUBLIC_COLUMNS = ["created", "updated", "to-publish", "state", "org", "repo"]
# Columns holding a number of days; they sort as numbers, so 9 comes before 10.
NUMERIC_COLUMNS = ("created", "updated", "to-publish")
DEFAULT_SORT = ["created", "org", "repo"]
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


def sort_cell(row, column):
    """How one column compares under --sort.

    Day counts compare as numbers, orgs in the order they were asked for on the
    command line, everything else alphabetically; empty cells ("", "?") last.
    """
    if column == "org":
        return (0, row["org_rank"])
    value = row[column]
    if column in NUMERIC_COLUMNS:
        return (1, 0) if value in ("", "?") else (0, int(value))
    return (1, "") if value == "" else (0, value)


def sort_key(row, columns):
    """A row's place in the table: the sorted columns, then ghsa to break ties.

    Without the tiebreak, advisories equal on every sorted column would come out
    in whichever order the concurrent fetches happened to finish in.
    """
    return tuple(sort_cell(row, c) for c in columns) + (row["ghsa"],)


def build_rows(advisories, orgs, redact=False, sort=None):
    """One row per advisory, ordered by the `sort` columns (default DEFAULT_SORT).

    A row holds the text of every column, ready to print, plus the few raw
    values a renderer decorates with: the advisory `url`, the `pulls` behind the
    PRs column, and `created_age`/`updated_age`, the day counts the terminal
    renderer colors the age badges by. `org_rank` is for the sort, which still
    needs the org order after --redact has overwritten the name.
    """
    rows = []
    for advisory in advisories:
        org = advisory.get("org")
        if org not in orgs:
            continue
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
            "org_rank": orgs.index(org),
        })
    # sorting by a redacted column would order the table by the very thing
    # --redact withholds, so redaction wins here as it does in select_columns
    order = sort or DEFAULT_SORT
    if redact:
        order = [c for c in order if c in PUBLIC_COLUMNS] or DEFAULT_SORT
    rows.sort(key=lambda row: sort_key(row, order))
    return rows
