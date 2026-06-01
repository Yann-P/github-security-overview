from security_overview import render_md

ORG = "acme"
STATES = ["draft"]
ADVISORY = {
    "ghsa_id": "GHSA-1234-5678-abcd",
    "html_url": "https://github.com/acme/repo-x/security/advisories/GHSA-1234-5678-abcd",
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


def test_table_header():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "| Age | State | Advisory | Title | CVE | PRs |" in out


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
    assert "[#1](https://github.com/acme/repo-x-private/pull/1)" in out
    assert "[#3](https://github.com/acme/repo-x-private/pull/3)" in out
    assert "PRs:" in out


def test_table_header_pr_column():
    out = render_md.render_org(ORG, STATES, RESULTS)
    assert "| PRs |" in out
