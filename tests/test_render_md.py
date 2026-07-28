from security_overview import render_md

ORG = "acme"
STATES = ["draft"]
ADVISORY = {
    "ghsa_id": "GHSA-1234-5678-abcd",
    "html_url": "https://github.com/acme/repo-x/security/advisories/GHSA-1234-5678-abcd",
    "created_at": "2024-05-01T00:00:00Z",
    "updated_at": "2024-06-01T00:00:00Z",
    "summary": "Remote code execution via evil input",
    "state": "draft",
    "cve_id": "CVE-2024-9999",
    "private_fork": None,
}
RESULTS = {(ORG, "draft"): [ADVISORY]}


def test_org_heading():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "## acme" in out


def test_repo_heading():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "### repo-x" in out


def test_table_header_matches_terminal_columns():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "| created | updated | to-publish | state | ghsa | cve | title | PRs |" in out


def test_table_header_omits_org_and_repo_columns():
    # org/repo are headings in markdown, so they are not repeated as columns
    header = [line for line in render_md.render_org(ORG, STATES, RESULTS).splitlines()
              if line.startswith("| created")][0]
    assert "| org |" not in header
    assert "| repo |" not in header


def test_row_has_created_updated_and_state():
    out = render_md.render_org(ORG, STATES, RESULTS)
    row = [line for line in out.splitlines() if "GHSA-1234-5678-abcd" in line][0]
    created, updated, ttp, state = [c.strip() for c in row.split("|")[1:5]]
    assert int(created) > int(updated) > 0
    assert ttp == ""  # draft advisories have no time-to-publish
    assert state == "draft"


def test_time_to_publish_for_published_advisory():
    published = {
        **ADVISORY,
        "state": "published",
        "published_at": "2024-05-11T00:00:00Z",
    }
    out = render_md.render_org(ORG, STATES, {(ORG, "draft"): [published]})
    row = [line for line in out.splitlines() if "GHSA-1234-5678-abcd" in line][0]
    assert row.split("|")[3].strip() == "10"


def test_title_pipe_is_escaped():
    results = {(ORG, "draft"): [{**ADVISORY, "summary": "a | b"}]}
    out = render_md.render_org(ORG, STATES, results)
    row = [line for line in out.splitlines() if "GHSA-1234-5678-abcd" in line][0]
    assert r"a \| b" in row


def test_linked_ghsa():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "[GHSA-1234-5678-abcd](" in out


def test_cve_in_row():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "CVE-2024-9999" in out


def test_no_advisories():
    out = render_md.render_org(ORG, STATES, {})
    assert out == ""


def test_redact_hides_org():
    out = render_md.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED ORG" in out
    assert ORG not in out.split("##")[1].split("\n")[0]


def test_redact_hides_advisory_details():
    # the point of --redact: nothing identifying an advisory may reach the table
    out = render_md.render_org(ORG, STATES, RESULTS, redact=True)
    for leak in ("GHSA", "CVE-2024-9999", "Remote code execution via evil input", "github.com"):
        assert leak not in out
    assert "| created | updated | to-publish | state |" in out


def test_redact_hides_repo():
    out = render_md.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED REPO" in out
    assert "repo-x" not in out


def test_pr_link():
    results = {
        (ORG, "draft"): [{
            **ADVISORY,
            "private_fork": {"html_url": "https://github.com/acme/repo-x-private"},
        }]
    }
    pull_results = {
        "https://github.com/acme/repo-x-private": [
            {
                "number": 1,
                "html_url": "https://github.com/acme/repo-x-private/pull/1",
                "state": "open",
                "merged_at": None,
            },
            {
                "number": 3,
                "html_url": "https://github.com/acme/repo-x-private/pull/3",
                "state": "open",
                "merged_at": None,
            },
        ]
    }
    out = render_md.render_org(ORG, STATES, results, pull_results=pull_results)
    # same `#N (state)` label the terminal renderer uses
    assert "[#1 (opened)](https://github.com/acme/repo-x-private/pull/1)" in out
    assert "[#3 (opened)](https://github.com/acme/repo-x-private/pull/3)" in out


def test_table_header_pr_column():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "| PRs |" in out
