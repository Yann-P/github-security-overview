import re

from security_overview.render_terminal import render
from security_overview.rows import build_rows, select_columns

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
    "severity": "high",
}
PULL = {"number": 7, "html_url": "https://github.com/acme/repo-x-private/pull/7",
        "state": "open", "merged_at": None}


def rows(*advisories, redact=False):
    return build_rows(list(advisories) or [ADVISORY], [ORG], redact)


def visible(text):
    text = re.sub(r"\033\]8;;[^\033]*\033\\", "", text)  # OSC 8 hyperlinks
    return re.sub(r"\033\[[0-9;]*m", "", text)  # SGR colors


def columns_of(line):
    """Visible start offset of each cell, keyed by the cell's stripped text."""
    return {m.group().strip(): m.start() for m in re.finditer(r"(?:\S+ ?)+", visible(line))}


def test_one_line_per_advisory():
    second = {**ADVISORY, "ghsa_id": "GHSA-aaaa-bbbb-cccc", "updated_at": "2024-05-01T00:00:00Z"}
    _, lines = render(rows(ADVISORY, second))
    assert len(lines) == 2
    assert "" not in lines


def test_no_advisories():
    header, lines = render([])
    assert lines == []
    assert visible(header).split() == ["created", "updated", "to-publish", "state",
                                       "severity", "org", "repo", "ghsa", "cve", "title", "PRs"]


def test_org_repo_and_title_on_every_line():
    _, lines = render(rows(), term_width=200)
    assert "acme" in lines[0]
    assert "repo-x" in lines[0]
    assert "Remote code execution via evil input" in lines[0]
    assert ADVISORY["html_url"] in lines[0]


def test_ghsa_and_cve_are_linked_on_the_same_line():
    _, lines = render(rows())
    assert "GHSA-1234-5678-abcd" in lines[0]
    assert "CVE-2024-9999" in lines[0]
    assert "nvd.nist.gov" in lines[0]


def test_pr_on_same_line():
    _, lines = render(rows({**ADVISORY, "pulls": [PULL]}))
    assert len(lines) == 1
    assert "#7 (opened)" in visible(lines[0])


def test_redact_hides_everything_identifying():
    _, lines = render(rows(redact=True), select_columns(redact=True))
    assert "REDACTED" in lines[0]
    for leak in ("acme", "repo-x", "Remote code execution", ADVISORY["html_url"]):
        assert leak not in lines[0]


def test_time_to_publish_column():
    published = {**ADVISORY, "state": "published", "published_at": "2024-03-11T00:00:00Z"}
    _, lines = render(rows(published))
    assert visible(lines[0]).split()[2] == "10"


def test_column_is_dropped_from_rows_and_header_when_no_row_fills_it():
    # no CVE anywhere in the run, and no published advisory: both columns disappear
    header, lines = render(rows({**ADVISORY, "cve_id": None}))
    assert "cve" not in visible(header).split()
    assert visible(lines[0]).split()[2] == "draft"


def test_nothing_is_printed_when_no_column_survives():
    # e.g. `--columns title --redact`: blank lines would still look like advisories
    for plain in (False, True):
        assert render(rows(ADVISORY, ADVISORY), select_columns(["title"], redact=True),
                      plain=plain) == ("", [])
    assert render(rows({**ADVISORY, "cve_id": None}), ["cve"]) == ("", [])


def test_columns_selects_and_orders_fields():
    header, lines = render(rows(), select_columns(["ghsa", "created"]))
    assert visible(header).split() == ["created", "ghsa"]
    assert "Remote code execution" not in lines[0]


TWO_ORGS = [
    ADVISORY,
    {
        **ADVISORY,
        "org": "umbrella-corporation",
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "html_url": "https://github.com/umbrella-corporation/a-much-longer-repo/security/advisories/GHSA-aaaa-bbbb-cccc",
        "cve_id": None,
    },
]


def test_columns_align_across_orgs():
    # widths measured per org would size `repo` to each org's longest name and
    # stagger the two blocks; one width per run keeps them in the same table
    header, lines = render(build_rows(TWO_ORGS, [ORG, "umbrella-corporation"]))
    assert columns_of(lines[0])["GHSA-1234-5678-abcd"] == columns_of(lines[1])["GHSA-aaaa-bbbb-cccc"]
    assert columns_of(header)["ghsa"] == columns_of(lines[0])["GHSA-1234-5678-abcd"]
    assert columns_of(header)["repo"] == columns_of(lines[0])["repo-x"]


def test_pr_column_aligns():
    short = {**ADVISORY, "summary": "short", "pulls": [PULL]}
    _, lines = render(rows({**ADVISORY, "pulls": [PULL]}, short))
    # the titles differ in length, so the PR cell only lines up if the title is padded
    assert visible(lines[0]).index("PRs: ") == visible(lines[1]).index("PRs: ")


def test_ages_right_aligned():
    ancient = {**ADVISORY, "created_at": "1999-01-01T00:00:00Z"}
    _, lines = render(rows(ADVISORY, ancient))
    # a 4-digit age and a 3-digit age must still end in the same column
    assert len({visible(line).index("draft") for line in lines}) == 1


def test_title_truncated_to_the_terminal_width():
    long_title = {**ADVISORY, "summary": "very long advisory title " * 20}
    _, lines = render(rows(long_title), term_width=100)
    assert len(visible(lines[0])) <= 100


def test_plain_tab_separated_columns():
    header, lines = render(rows(), plain=True)
    fields = lines[0].split("\t")
    assert header.split("\t") == ["created", "updated", "to-publish", "state",
                                  "severity", "org", "repo", "ghsa", "cve", "title", "PRs"]
    assert fields[0].isdigit()
    assert fields[1].isdigit()
    assert fields[2] == "NA"  # time-to-publish: this advisory is a draft
    assert fields[3:10] == ["draft", "high", "acme", "repo-x", "GHSA-1234-5678-abcd", "CVE-2024-9999",
                           "Remote code execution via evil input"]
    assert "\033" not in header + lines[0]


def test_plain_field_positions_survive_empty_columns():
    # an org with no GHSA/CVE anywhere must still emit those cells, or the title
    # slides into their field number and piped awk/cut/datamash reads the wrong column
    header, lines = render(rows({**ADVISORY, "ghsa_id": None, "cve_id": None}), plain=True)
    fields = lines[0].split("\t")
    assert fields[7:9] == ["", ""]
    assert fields[header.split("\t").index("title")] == "Remote code execution via evil input"


def test_plain_title_not_truncated():
    long_title = ("very long advisory title " * 20).strip()
    _, lines = render(rows({**ADVISORY, "summary": long_title}), plain=True, term_width=100)
    assert long_title in lines[0]


def test_plain_pr_cell():
    _, lines = render(rows({**ADVISORY, "pulls": [PULL]}), plain=True)
    assert lines[0].split("\t")[-1] == "PRs: #7 (opened)"


def test_plain_redact():
    header, lines = render(rows(redact=True), select_columns(redact=True), plain=True)
    assert header.split("\t") == ["created", "updated", "to-publish", "state", "severity",
                                  "org", "repo"]
    assert lines[0].split("\t")[5:] == ["REDACTED", "REDACTED"]
    assert "\033" not in lines[0]
