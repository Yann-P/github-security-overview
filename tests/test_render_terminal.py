import re

from security_overview import render_terminal

ORG = "acme"
STATES = ["draft"]
ADVISORY = {
    "ghsa_id": "GHSA-1234-5678-abcd",
    "html_url": "https://github.com/acme/repo-x/security/advisories/GHSA-1234-5678-abcd",
    "created_at": "2024-03-01T00:00:00Z",
    "updated_at": "2024-06-01T00:00:00Z",
    "summary": "Remote code execution via evil input",
    "state": "draft",
    "cve_id": "CVE-2024-9999",
    "private_fork": None,
}
RESULTS = {(ORG, "draft"): [ADVISORY]}


def test_org_column():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "acme" in out


def test_repo_column():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "repo-x" in out


def test_title_linked():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    assert "Remote code execution via evil input" in out
    assert ADVISORY["html_url"] in out


def test_no_advisories():
    out = render_terminal.render_org(ORG, STATES, {})
    assert out == ""


def test_one_line_per_advisory():
    results = {
        (ORG, "draft"): [
            ADVISORY,
            {**ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc", "updated_at": "2024-05-01T00:00:00Z"},
            {
                **ADVISORY,
                "ghsa_id": "GHSA-dddd-eeee-ffff",
                "html_url": "https://github.com/acme/repo-y/security/advisories/GHSA-dddd-eeee-ffff",
            },
        ]
    }
    out = render_terminal.render_org(ORG, STATES, results)
    assert len(out.splitlines()) == 3
    assert "" not in out.splitlines()


def test_org_repo_on_every_line():
    results = {
        (ORG, "draft"): [
            ADVISORY,
            {**ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc", "updated_at": "2024-05-01T00:00:00Z"},
        ]
    }
    out = render_terminal.render_org(ORG, STATES, results)
    for line in out.splitlines():
        assert "acme" in line
        assert "repo-x" in line


def test_sorted_by_updated_desc():
    results = {
        (ORG, "draft"): [
            {**ADVISORY, "summary": "older vuln", "updated_at": "2024-01-01T00:00:00Z"},
            {**ADVISORY, "summary": "newer vuln", "updated_at": "2024-06-01T00:00:00Z"},
        ]
    }
    out = render_terminal.render_org(ORG, STATES, results)
    lines = out.splitlines()
    assert "newer vuln" in lines[0]
    assert "older vuln" in lines[1]


def test_cve_on_same_line():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    lines = out.splitlines()
    assert len(lines) == 1
    assert "CVE-2024-9999" in lines[0]
    assert "nvd.nist.gov" in lines[0]


def test_pr_on_same_line():
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
    assert len(lines) == 1
    assert "#7" in lines[0]
    assert "opened" in lines[0]


def test_redact_hides_org():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "REDACTED" in out
    assert "acme" not in out


def test_redact_hides_repo():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "repo-x" not in out


def test_redact_hides_title():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True)
    assert "Remote code execution" not in out
    assert ADVISORY["html_url"] not in out


def test_redact_one_line_per_advisory():
    results = {
        (ORG, "draft"): [
            ADVISORY,
            {**ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc", "updated_at": "2024-05-01T00:00:00Z"},
        ]
    }
    out = render_terminal.render_org(ORG, STATES, results, redact=True)
    assert len(out.splitlines()) == 2


def test_plain_tab_separated_columns():
    out = render_terminal.render_org(ORG, STATES, RESULTS, plain=True)
    fields = out.split("\t")
    assert fields[0].isdigit()
    assert fields[1].isdigit()
    assert fields[2] == "NA"  # time-to-publish: draft advisory
    assert fields[3] == "draft"
    assert fields[4] == "acme"
    assert fields[5] == "repo-x"
    assert fields[6] == "CVE-2024-9999"
    assert fields[7] == "Remote code execution via evil input"


def test_plain_created_before_updated():
    out = render_terminal.render_org(ORG, STATES, RESULTS, plain=True)
    created_days, updated_days = out.split("\t")[:2]
    # created_at (2024-03-01) predates updated_at (2024-06-01)
    assert int(created_days) > int(updated_days)


def test_header_plain():
    h = render_terminal.header(plain=True)
    assert h.split("\t") == [
        "created", "updated", "to-publish", "state", "org", "repo", "cve", "title", "PRs"
    ]
    assert "\033" not in h


def test_header_redact_drops_detail_columns():
    h = render_terminal.header(redact=True, plain=True)
    assert h.split("\t") == ["created", "updated", "to-publish", "state", "org", "repo"]


PUBLISHED_ADVISORY = {
    **ADVISORY,
    "state": "published",
    "published_at": "2024-03-11T00:00:00Z",  # 10 days after created_at
}


def test_plain_time_to_publish():
    results = {(ORG, "published"): [PUBLISHED_ADVISORY]}
    out = render_terminal.render_org(ORG, ["published"], results, plain=True)
    assert out.split("\t")[2] == "10"


def test_plain_no_time_to_publish_unless_published():
    # closed advisory keeps its published_at, but the column only applies to published
    results = {(ORG, "closed"): [{**PUBLISHED_ADVISORY, "state": "closed"}]}
    out = render_terminal.render_org(ORG, ["closed"], results, plain=True)
    assert out.split("\t")[2] == "NA"


def _visible(out):
    out = re.sub(r"\033\]8;;[^\033]*\033\\", "", out)  # OSC 8 hyperlinks
    return re.sub(r"\033\[[0-9;]*m", "", out)  # SGR colors


def test_terminal_time_to_publish_column():
    results = {(ORG, "published"): [PUBLISHED_ADVISORY]}
    out = render_terminal.render_org(ORG, ["published"], results)
    assert _visible(out).split()[2] == "10"


def test_terminal_no_ttp_column_without_published():
    assert _visible(render_terminal.render_org(ORG, STATES, RESULTS)).split()[2] == "draft"


def test_plain_no_ansi_escapes():
    out = render_terminal.render_org(ORG, STATES, RESULTS, plain=True)
    assert "\033" not in out


def test_plain_title_not_truncated():
    long_title = ("very long advisory title " * 20).strip()
    results = {(ORG, "draft"): [{**ADVISORY, "summary": long_title}]}
    out = render_terminal.render_org(ORG, STATES, results, plain=True)
    assert long_title in out


def test_plain_pr_cell():
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
    out = render_terminal.render_org(ORG, STATES, results, pull_results=pull_results, plain=True)
    assert out.split("\t")[-1] == "PRs: #7 (opened)"
    assert "\033" not in out


def test_plain_redact():
    out = render_terminal.render_org(ORG, STATES, RESULTS, redact=True, plain=True)
    assert "\t" in out
    assert "\033" not in out
    assert "acme" not in out
