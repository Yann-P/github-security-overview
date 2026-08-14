from datetime import datetime, timedelta, timezone

from security_overview.rows import COLUMNS, build_rows, days_ago, pull_summary, select_columns

ORG = "acme"
ADVISORY = {
    "org": ORG,
    "ghsa_id": "GHSA-1234-5678-abcd",
    "html_url": "https://github.com/acme/repo-x/security/advisories/GHSA-1234-5678-abcd",
    "created_at": "2024-03-01T00:00:00Z",
    "updated_at": "2024-06-01T00:00:00Z",
    "summary": "Remote code execution via evil input",
    "state": "draft",
    "cve_id": "CVE-2024-9999",
}


def test_select_columns_defaults_to_all():
    assert select_columns() == COLUMNS


def test_select_columns_keeps_canonical_order():
    assert select_columns(["title", "created", "state"]) == ["created", "state", "title"]


def test_select_columns_ignores_unknown_names():
    assert select_columns(["created", "bogus"]) == ["created"]


def test_select_columns_redact_wins_over_selection():
    # asking for title under --redact must not resurrect it
    assert select_columns(["title", "ghsa", "state"], redact=True) == ["state"]


def test_days_ago_missing():
    assert days_ago("") is None


def test_days_ago_recent():
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert days_ago(yesterday) == 1


def test_pull_summary_open():
    pull = {"number": 7, "html_url": "http://pr/7", "state": "open", "merged_at": None}
    assert pull_summary(pull) == {"label": "#7 (opened)", "url": "http://pr/7", "state": "open"}


def test_pull_summary_merged():
    # GitHub reports merged pull requests as closed
    pull = {"number": 7, "html_url": "http://pr/7", "state": "closed", "merged_at": "2024-01-01"}
    assert pull_summary(pull)["label"] == "#7 (merged)"


def test_row_columns():
    row = build_rows([ADVISORY], [ORG])[0]
    assert row["state"] == "draft"
    assert row["org"] == ORG
    assert row["repo"] == "repo-x"
    assert row["ghsa"] == "GHSA-1234-5678-abcd"
    assert row["cve"] == "CVE-2024-9999"
    assert row["title"] == "Remote code execution via evil input"
    assert int(row["created"]) > int(row["updated"]) > 0


def test_row_time_to_publish():
    published = {**ADVISORY, "state": "published", "published_at": "2024-03-11T00:00:00Z"}
    assert build_rows([published], [ORG])[0]["to-publish"] == "10"


def test_row_no_time_to_publish_unless_published():
    # a closed advisory keeps its published_at, but the column only applies to published ones
    closed = {**ADVISORY, "state": "closed", "published_at": "2024-03-11T00:00:00Z"}
    assert build_rows([closed], [ORG])[0]["to-publish"] == ""


def test_row_title_is_single_line():
    messy = {**ADVISORY, "summary": "two\tlines\nin one title"}
    assert build_rows([messy], [ORG])[0]["title"] == "two lines in one title"


def test_rows_sorted_by_updated_desc():
    older = {**ADVISORY, "summary": "older", "updated_at": "2024-01-01T00:00:00Z"}
    newer = {**ADVISORY, "summary": "newer", "updated_at": "2024-06-01T00:00:00Z"}
    assert [r["title"] for r in build_rows([older, newer], [ORG])] == ["newer", "older"]


def test_rows_do_not_depend_on_the_order_advisories_were_fetched_in():
    # same updated_at: without a tiebreak these would swap places between runs
    first = {**ADVISORY, "ghsa_id": "GHSA-aaaa"}
    second = {**ADVISORY, "ghsa_id": "GHSA-bbbb"}
    assert build_rows([first, second], [ORG]) == build_rows([second, first], [ORG])


def test_rows_follow_the_org_order_asked_for():
    other = {**ADVISORY, "org": "umbrella", "updated_at": "2030-01-01T00:00:00Z"}
    rows = build_rows([other, ADVISORY], [ORG, "umbrella"])
    assert [r["org"] for r in rows] == [ORG, "umbrella"]


def test_rows_redact_org_and_repo():
    row = build_rows([ADVISORY], [ORG], redact=True)[0]
    assert row["org"] == "REDACTED"
    assert row["repo"] == "REDACTED"


def test_row_pulls():
    advisory = {**ADVISORY, "pulls": [
        {"number": 7, "html_url": "http://pr/7", "state": "open", "merged_at": None},
        {"number": 9, "html_url": "http://pr/9", "state": "closed", "merged_at": None},
    ]}
    assert build_rows([advisory], [ORG])[0]["PRs"] == "#7 (opened), #9 (closed)"


def test_row_unknown_repo_without_url():
    assert build_rows([{"org": ORG}], [ORG])[0]["repo"] == "unknown"
