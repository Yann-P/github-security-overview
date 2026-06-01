from security_overview import render_terminal

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


def test_org_header():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "=== acme ===" in out


def test_repo_name():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "repo-x" in out


def test_title_linked():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "Remote code execution via evil input" in out
    assert ADVISORY["html_url"] in out


def test_no_advisories():
    out = render_terminal.render_org(ORG, STATES, {})
    assert out == ""


def test_tree_connector_single():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "└── " in out


def test_tree_connector_multiple():
    results = {
        (ORG, "draft"): [
            ADVISORY,
            {**ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc", "updated_at": "2024-05-01T00:00:00Z"},
        ]
    }
    out = render_terminal.render_org(ORG, STATES, results)
    assert "├── " in out
    assert "└── " in out


def test_cve_on_sub_line():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    lines = out.splitlines()
    cve_line = next(l for l in lines if "CVE-2024-9999" in l)
    assert "└── " in cve_line
    assert "nvd.nist.gov" in cve_line


def test_pr_on_sub_line():
    results = {
        (ORG, "draft"): [{
            **ADVISORY,
            "private_fork": {"html_url": "https://github.com/acme/repo-x-private"},
        }]
    }
    pull_results = {
        "https://github.com/acme/repo-x-private": [
            {"number": 7, "html_url": "https://github.com/acme/repo-x-private/pull/7",
             "state": "open", "merged_at": None},
        ]
    }
    out = render_terminal.render_org(ORG, STATES, results, pull_results=pull_results)
    lines = out.splitlines()
    sub_line = next(l for l in lines if "#7" in l)
    assert "opened" in sub_line
    assert "└── " in sub_line


def test_redact_hides_org():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED ORG" in out


def test_redact_hides_repo():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED REPO" in out
    assert "repo-x" not in out


def test_redact_hides_title():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "Remote code execution" not in out
    assert ADVISORY["html_url"] not in out
