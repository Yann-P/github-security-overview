import argparse

import pytest

from security_overview.cli import in_date_range, name_list, parse_date
from security_overview.fetch import STATES

parse_states = name_list(STATES, "state")


def test_parse_single_state():
    assert parse_states("draft") == ["draft"]


def test_parse_comma_separated_with_spaces():
    assert parse_states("draft, triage") == ["draft", "triage"]


def test_parse_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid state"):
        parse_states("draft,bogus")


def test_parse_invalid_column_names_the_flag():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid column"):
        name_list(["created"], "column")("titel")


def test_parse_date_valid():
    assert parse_date("2024-06-01") == "2024-06-01"


def test_parse_date_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError, match="invalid date"):
        parse_date("June 1st")


def test_date_range_bounds_are_inclusive():
    assert in_date_range("2024-06-01T08:00:00Z", "2024-06-01", "2024-06-01")


def test_date_range_open_ended():
    assert in_date_range("2024-06-01T08:00:00Z", None, None)
    assert in_date_range("2024-06-01T08:00:00Z", "2024-01-01", None)
    assert not in_date_range("2024-06-01T08:00:00Z", None, "2024-05-31")


def test_date_range_drops_missing_timestamps():
    # e.g. a never-published advisory when --published-from is given
    assert not in_date_range(None, "2024-01-01", None)
    assert not in_date_range("", None, None)
