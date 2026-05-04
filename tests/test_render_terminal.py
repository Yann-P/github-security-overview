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


def test_ghsa_id_present():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "GHSA-1234-5678-abcd" in out


def test_no_advisories():
    out = render_terminal.render_org(ORG, STATES, {})
    assert "(no advisories)" in out


def test_redact_hides_org():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED ORG" in out


def test_redact_hides_repo():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED REPO" in out
    assert "repo-x" not in out


def test_redact_masks_ghsa():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "GHSA-xxxx-yyyy-zzzz" in out
    assert "GHSA-1234-5678-abcd" not in out
