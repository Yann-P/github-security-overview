import pytest
import argparse
from security_overview.cli import parse_states


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
