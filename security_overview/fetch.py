import os
import sys

import httpx

GITHUB_API = "https://api.github.com"


def check_token():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("error: GITHUB_TOKEN environment variable not set", file=sys.stderr)
        sys.exit(1)
    return token


async def fetch_first_pull(client, fork_html_url, results):
    path = fork_html_url.split("github.com/", 1)[-1].rstrip("/")
    url = f"{GITHUB_API}/repos/{path}/pulls"
    params = {"per_page": 1, "state": "all", "sort": "created", "direction": "asc"}
    try:
        req = client.build_request("GET", url, params=params)
        resp = await client.send(req)
        if resp.status_code == 200:
            pulls = resp.json()
            results[fork_html_url] = pulls[0] if pulls else None
        else:
            results[fork_html_url] = None
    except httpx.HTTPError:
        results[fork_html_url] = None


async def fetch(client, org, state, results):
    url = f"{GITHUB_API}/orgs/{org}/security-advisories"
    params = {"state": state, "per_page": 100}
    advisories = []
    while url is not None:
        try:
            req = client.build_request("GET", url, params=params)
            resp = await client.send(req)
        except httpx.HTTPError as e:
            print(f"[error] {org} ({state}): {e}", file=sys.stderr)
            break
        if resp.status_code != 200:
            print(
                f"[error] {org} ({state}): HTTP {resp.status_code} {resp.text.strip()}",
                file=sys.stderr,
            )
            break
        try:
            page = resp.json()
        except ValueError:
            break
        if isinstance(page, list):
            advisories.extend(page)
        next_link = resp.links.get("next")
        url = next_link["url"] if next_link else None
        params = None
    results[(org, state)] = advisories
