from security_overview.render_md import render
from security_overview.rows import build_rows, days_ago, select_columns

ORG = "acme"
ADVISORY = {
    "org": ORG,
    "ghsa_id": "GHSA-1234-5678-abcd",
    "html_url": "https://github.com/acme/repo-x/security/advisories/GHSA-1234-5678-abcd",
    "created_at": "2024-05-01T00:00:00Z",
    "updated_at": "2024-06-01T00:00:00Z",
    "summary": "Remote code execution via evil input",
    "state": "draft",
    "cve_id": "CVE-2024-9999",
}


def rows(*advisories, redact=False):
    return build_rows(list(advisories) or [ADVISORY], [ORG], redact)


def row_for(out, ghsa="GHSA-1234-5678-abcd"):
    return [line for line in out.splitlines() if ghsa in line][0]


def test_org_and_repo_headings():
    out = render(rows())
    assert "## acme" in out
    assert "### repo-x" in out


def test_table_header_omits_org_and_repo_columns():
    # org/repo are headings in markdown, so they are not repeated as columns
    assert "| created | updated | to-publish | state | ghsa | cve | title | PRs |" in render(rows())


def test_row_cells():
    created, updated, ttp, state = [c.strip() for c in row_for(render(rows())).split("|")[1:5]]
    assert int(created) > int(updated) > 0
    assert ttp == ""  # draft advisories have no time-to-publish
    assert state == "draft"


def test_time_to_publish_for_published_advisory():
    published = {**ADVISORY, "state": "published", "published_at": "2024-05-11T00:00:00Z"}
    assert row_for(render(rows(published))).split("|")[3].strip() == "10"


def test_title_pipe_is_escaped():
    assert r"a \| b" in row_for(render(rows({**ADVISORY, "summary": "a | b"})))


def test_ghsa_and_cve_are_linked():
    out = render(rows())
    assert f"[GHSA-1234-5678-abcd]({ADVISORY['html_url']})" in out
    assert "[CVE-2024-9999](https://nvd.nist.gov/vuln/detail/CVE-2024-9999)" in out


def test_no_advisories():
    assert render([]) == ""


def test_repos_ordered_by_most_recent_advisory():
    stale = {**ADVISORY, "html_url": "https://github.com/acme/repo-old/x", "ghsa_id": "GHSA-old",
             "updated_at": "2024-01-01T00:00:00Z"}
    headings = [line for line in render(rows(stale, ADVISORY)).splitlines() if line.startswith("###")]
    assert headings == ["### repo-x", "### repo-old"]


def test_redact_hides_advisory_details():
    # the point of --redact: nothing identifying an advisory may reach the table
    out = render(rows(redact=True), select_columns(redact=True))
    for leak in ("GHSA", "CVE-2024-9999", "Remote code execution via evil input", "github.com",
                 "acme", "repo-x"):
        assert leak not in out
    assert "## REDACTED" in out
    assert "| created | updated | to-publish | state |" in out


def test_columns_selects_table_columns():
    out = render(rows(), select_columns(["state", "created", "title"]))
    assert "| created | state | title |" in out
    assert "| cve |" not in out
    assert [c.strip() for c in row_for(out, "draft").split("|")[1:-1]] == [
        str(days_ago(ADVISORY["created_at"])), "draft", "Remote code execution via evil input"
    ]


def test_columns_org_repo_only_renders_nothing():
    # org/repo live in the headings, so a table of just those has no cells to show
    assert render(rows(), ["org", "repo"]) == ""


def test_pr_links():
    pulls = [
        {"number": 1, "html_url": "https://github.com/acme/repo-x-private/pull/1",
         "state": "open", "merged_at": None},
        {"number": 3, "html_url": "https://github.com/acme/repo-x-private/pull/3",
         "state": "closed", "merged_at": "2024-06-01T00:00:00Z"},
    ]
    out = render(rows({**ADVISORY, "pulls": pulls}))
    assert "[#1 (opened)](https://github.com/acme/repo-x-private/pull/1)" in out
    assert "[#3 (merged)](https://github.com/acme/repo-x-private/pull/3)" in out
