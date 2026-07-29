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


def test_ghsa_on_same_line():
    out = render_terminal.render_org(ORG, STATES, RESULTS)
    lines = out.splitlines()
    assert len(lines) == 1
    assert "GHSA-1234-5678-abcd" in lines[0]
    assert ADVISORY["html_url"] in lines[0]


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
    assert fields[6] == "GHSA-1234-5678-abcd"
    assert fields[7] == "CVE-2024-9999"
    assert fields[8] == "Remote code execution via evil input"


def test_plain_field_positions_survive_empty_columns():
    # an org with no GHSA/CVE anywhere must still emit those cells, or the title
    # slides into their field number and piped awk/cut/datamash reads the wrong column
    results = {(ORG, "draft"): [{**ADVISORY, "ghsa_id": None, "cve_id": None}]}
    out = render_terminal.render_org(ORG, STATES, results, plain=True)
    fields = out.split("\t")
    title_col = render_terminal.header(plain=True).split("\t").index("title")
    assert fields[6] == ""
    assert fields[7] == ""
    assert fields[title_col] == "Remote code execution via evil input"


def test_columns_selects_and_orders_fields():
    # requested out of order; emitted in canonical order
    out = render_terminal.render_org(ORG, STATES, RESULTS, plain=True, columns=["ghsa", "created"])
    created, ghsa = out.split("\t")
    assert created.isdigit()
    assert ghsa == "GHSA-1234-5678-abcd"


def test_columns_header_matches_row_fields():
    cols = ["created", "state", "ghsa", "title"]
    header = render_terminal.header(plain=True, columns=cols).split("\t")
    fields = render_terminal.render_org(ORG, STATES, RESULTS, plain=True, columns=cols).split("\t")
    assert header == cols
    assert len(fields) == len(cols)
    assert fields[header.index("title")] == "Remote code execution via evil input"


def test_columns_drop_title_from_output():
    out = render_terminal.render_org(ORG, STATES, RESULTS, columns=["created", "state"])
    assert "Remote code execution" not in out


def test_plain_created_before_updated():
    out = render_terminal.render_org(ORG, STATES, RESULTS, plain=True)
    created_days, updated_days = out.split("\t")[:2]
    # created_at (2024-03-01) predates updated_at (2024-06-01)
    assert int(created_days) > int(updated_days)


def test_header_plain():
    h = render_terminal.header(plain=True)
    assert h.split("\t") == [
        "created", "updated", "to-publish", "state", "org", "repo", "ghsa", "cve", "title", "PRs"
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


TWO_ORGS = {
    ("acme", "draft"): [ADVISORY],
    ("umbrella-corporation", "draft"): [
        {
            **ADVISORY,
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "html_url": "https://github.com/umbrella-corporation/a-much-longer-repo/security/advisories/GHSA-aaaa-bbbb-cccc",
            "cve_id": None,
        }
    ],
}


def _columns(line):
    """Visible start offset of each cell, keyed by the cell's stripped text."""
    line = _visible(line)
    return {m.group().strip(): m.start() for m in re.finditer(r"(?:\S+ ?)+", line)}


def test_terminal_columns_align_across_orgs():
    # widths measured per org would size `repo` to each org's longest name and
    # stagger the two blocks; one width per run keeps them in the same table
    widths = render_terminal.column_widths(STATES, TWO_ORGS)
    lines = [
        render_terminal.render_org(org, STATES, TWO_ORGS, widths=widths)
        for org in ("acme", "umbrella-corporation")
    ]
    assert _columns(lines[0])["GHSA-1234-5678-abcd"] == _columns(lines[1])["GHSA-aaaa-bbbb-cccc"]


def test_terminal_columns_align_without_shared_widths():
    # results_by_key holds every org, so a bare render_org call measures the same
    lines = [
        render_terminal.render_org(org, STATES, TWO_ORGS)
        for org in ("acme", "umbrella-corporation")
    ]
    assert _columns(lines[0])["GHSA-1234-5678-abcd"] == _columns(lines[1])["GHSA-aaaa-bbbb-cccc"]


def test_terminal_header_sits_over_its_column():
    widths = render_terminal.column_widths(STATES, TWO_ORGS)
    header = render_terminal.header(widths=widths)
    row = render_terminal.render_org("acme", STATES, TWO_ORGS, widths=widths)
    assert _columns(header)["ghsa"] == _columns(row)["GHSA-1234-5678-abcd"]
    assert _columns(header)["repo"] == _columns(row)["repo-x"]


def test_terminal_pr_column_aligns():
    fork = {"html_url": "https://github.com/acme/repo-x-private"}
    results = {
        (ORG, "draft"): [
            {**ADVISORY, "private_fork": fork},
            {**ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": "short", "private_fork": fork},
        ]
    }
    pull_results = {fork["html_url"]: [
        {"number": 7, "html_url": "https://github.com/acme/repo-x-private/pull/7",
         "state": "open", "merged_at": None},
    ]}
    first, second = render_terminal.render_org(
        ORG, STATES, results, pull_results=pull_results
    ).splitlines()
    # titles differ in length, so the PR cell only lines up if the title is padded
    assert _visible(first).index("PRs: ") == _visible(second).index("PRs: ")


def test_terminal_ages_right_aligned():
    results = {(ORG, "draft"): [
        ADVISORY,
        {**ADVISORY, "created_at": "1999-01-01T00:00:00Z", "updated_at": "2024-05-01T00:00:00Z"},
    ]}
    lines = render_terminal.render_org(ORG, STATES, results).splitlines()
    # a 4-digit age and a 3-digit age must still end in the same column
    assert len({_visible(line).index("draft") for line in lines}) == 1


def test_terminal_dropped_column_dropped_from_header_too():
    # no CVE anywhere in the run: the cve column disappears from rows *and* header
    results = {(ORG, "draft"): [{**ADVISORY, "cve_id": None}]}
    widths = render_terminal.column_widths(STATES, results)
    assert "cve" not in _visible(render_terminal.header(widths=widths)).split()


def test_plain_ignores_widths():
    widths = render_terminal.column_widths(STATES, TWO_ORGS)
    out = render_terminal.render_org(ORG, STATES, TWO_ORGS, plain=True, widths=widths)
    assert out.split("\t")[5] == "repo-x"  # no padding despite the longer repo elsewhere
    assert "\033" not in out


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
