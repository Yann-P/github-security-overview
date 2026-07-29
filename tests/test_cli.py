import pytest
import argparse
from security_overview.cli import filter_date_range, parse_columns, parse_date, parse_states


def test_parse_single_state():
    assert parse_states("draft") == ["draft"]


def test_parse_comma_separated():
    assert parse_states("draft,triage") == ["draft", "triage"]


def test_parse_with_spaces():
    assert parse_states("draft, triage") == ["draft", "triage"]


def test_parse_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid state"):
        parse_states("bogus")


def test_parse_mixed_valid_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_states("draft,bogus")


def test_parse_columns_comma_separated():
    assert parse_columns("created, ghsa") == ["created", "ghsa"]


def test_parse_columns_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid column"):
        parse_columns("titel")


def test_parse_date_valid():
    assert parse_date("2024-06-01") == "2024-06-01"


def test_parse_date_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid date"):
        parse_date("June 1st")


RESULTS = {
    ("acme", "draft"): [
        {"ghsa_id": "GHSA-old", "created_at": "2024-01-15T12:00:00Z"},
        {"ghsa_id": "GHSA-mid", "created_at": "2024-06-01T08:00:00Z"},
        {"ghsa_id": "GHSA-new", "created_at": "2024-12-31T23:59:00Z"},
    ]
}


def _ids(results):
    return [a["ghsa_id"] for a in results[("acme", "draft")]]


def test_filter_opened_noop_without_bounds():
    assert filter_date_range(RESULTS, "created_at", None, None) is RESULTS


def test_filter_opened_from():
    out = filter_date_range(RESULTS, "created_at", "2024-06-01", None)
    assert _ids(out) == ["GHSA-mid", "GHSA-new"]


def test_filter_opened_to():
    out = filter_date_range(RESULTS, "created_at", None, "2024-06-01")
    assert _ids(out) == ["GHSA-old", "GHSA-mid"]


def test_filter_opened_range():
    out = filter_date_range(RESULTS, "created_at", "2024-02-01", "2024-06-30")
    assert _ids(out) == ["GHSA-mid"]


def test_filter_opened_bounds_inclusive():
    out = filter_date_range(RESULTS, "created_at", "2024-01-15", "2024-12-31")
    assert _ids(out) == ["GHSA-old", "GHSA-mid", "GHSA-new"]


def test_filter_opened_drops_missing_created_at():
    results = {("acme", "draft"): [{"ghsa_id": "GHSA-x"}]}
    out = filter_date_range(results, "created_at", "2024-01-01", None)
    assert out[("acme", "draft")] == []


PUBLISHED_RESULTS = {
    ("acme", "published"): [
        {"ghsa_id": "GHSA-early", "published_at": "2024-02-01T12:00:00Z"},
        {"ghsa_id": "GHSA-late", "published_at": "2024-09-01T12:00:00Z"},
        {"ghsa_id": "GHSA-unpublished", "published_at": None},
    ]
}


def test_filter_published_range():
    out = filter_date_range(PUBLISHED_RESULTS, "published_at", "2024-01-01", "2024-06-30")
    assert [a["ghsa_id"] for a in out[("acme", "published")]] == ["GHSA-early"]


def test_filter_published_drops_unpublished_when_bounded():
    out = filter_date_range(PUBLISHED_RESULTS, "published_at", None, "2024-12-31")
    assert [a["ghsa_id"] for a in out[("acme", "published")]] == ["GHSA-early", "GHSA-late"]
