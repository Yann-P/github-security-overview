import sys

import httpx
import trio

API = "https://api.github.com"
STATES = ["published", "draft", "triage", "closed"]


def github_client(token):
    """A client for the GitHub API; use it with `async with`."""
    return httpx.AsyncClient(
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "security-overview",
        },
        timeout=30.0,
    )


async def get_all(client, url, params):
    """Every page of a list endpoint, concatenated. Errors are reported and yield []."""
    items = []
    while url:
        request = client.build_request("GET", url, params=params)
        try:
            response = await client.send(request)
        except httpx.HTTPError as error:
            print(f"[error] {request.url}: {error}", file=sys.stderr)
            break
        if response.status_code != 200:
            detail = f"HTTP {response.status_code} {response.text.strip()}"
            print(f"[error] {request.url}: {detail}", file=sys.stderr)
            break
        items.extend(response.json())
        url = (response.links.get("next") or {}).get("url")
        params = None  # the next-page link already carries them
    return items


async def fetch_advisories(client, orgs, states):
    """Advisories for every org/state pair, fetched in parallel and tagged with their org."""
    advisories = []

    async def collect(org, state):
        url = f"{API}/orgs/{org}/security-advisories"
        for advisory in await get_all(client, url, {"state": state, "per_page": 100}):
            advisories.append({**advisory, "org": org})

    async with trio.open_nursery() as nursery:
        for org in orgs:
            for state in states:
                nursery.start_soon(collect, org, state)
    return advisories


def fork_url(advisory):
    """Where the advisory's private fork lives, or "" when it has none."""
    return (advisory.get("private_fork") or {}).get("html_url") or ""


async def fetch_pulls(client, advisories):
    """Attach each advisory's private-fork pull requests as advisory["pulls"]."""
    pulls_by_fork = {}

    async def collect(fork):
        repo_path = fork.split("github.com/", 1)[-1].rstrip("/")
        params = {"per_page": 100, "state": "all", "sort": "created", "direction": "asc"}
        pulls_by_fork[fork] = await get_all(client, f"{API}/repos/{repo_path}/pulls", params)

    async with trio.open_nursery() as nursery:
        for fork in {fork_url(a) for a in advisories} - {""}:
            nursery.start_soon(collect, fork)

    for advisory in advisories:
        advisory["pulls"] = pulls_by_fork.get(fork_url(advisory), [])
