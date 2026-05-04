from datetime import datetime, timezone, timedelta
from security_overview.render_common import (
    plasma_rgb, age_t, pr_state, days_ago, group_by_repo,
)


def test_plasma_rgb_old():
    r, g, b = plasma_rgb(0)
    assert b > r


def test_plasma_rgb_recent():
    r, g, b = plasma_rgb(1)
    assert r > b


def test_plasma_rgb_clamps_to_byte_range():
    for t in (0, 0.5, 1):
        for v in plasma_rgb(t):
            assert 0 <= v <= 255


def test_age_t_recent():
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert age_t(yesterday) > 0.99


def test_age_t_old():
    ancient = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    assert age_t(ancient) == 0.0


def test_pr_state_none():
    assert pr_state(None) is None


def test_pr_state_merged():
    assert pr_state({"merged_at": "2024-01-01T00:00:00Z", "state": "closed"}) == "merged"


def test_pr_state_open():
    assert pr_state({"state": "open"}) == "open"


def test_pr_state_closed():
    assert pr_state({"state": "closed"}) == "closed"


def test_days_ago_missing():
    assert days_ago("") == "?"


def test_days_ago_recent():
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert days_ago(yesterday) == 1


def test_group_by_repo_order():
    advisories = [
        {"html_url": "https://github.com/org/repo-a/...", "updated_at": "2024-01-01T00:00:00Z"},
        {"html_url": "https://github.com/org/repo-b/...", "updated_at": "2024-06-01T00:00:00Z"},
        {"html_url": "https://github.com/org/repo-a/...", "updated_at": "2024-03-01T00:00:00Z"},
    ]
    grouped = group_by_repo(advisories)
    repos = [r for r, _ in grouped]
    assert repos[0] == "repo-b"
    assert repos[1] == "repo-a"
