import httpx
import respx
import trio

from security_overview.fetch import fetch_advisories, fetch_pulls, github_client

ADVISORIES = "https://api.github.com/orgs/acme/security-advisories"
PULLS = "https://api.github.com/repos/acme/repo-x-private/pulls"


def run(coroutine_function):
    """Run one async call against a fake GitHub."""
    async def go():
        async with github_client("token") as client:
            return await coroutine_function(client)
    return trio.run(go)


@respx.mock
def test_advisories_follow_pagination_and_are_tagged_with_their_org():
    respx.get(ADVISORIES).mock(side_effect=[
        httpx.Response(200, json=[{"ghsa_id": "GHSA-1"}],
                       headers={"Link": f'<{ADVISORIES}?page=2>; rel="next"'}),
        httpx.Response(200, json=[{"ghsa_id": "GHSA-2"}]),
    ])

    advisories = run(lambda client: fetch_advisories(client, ["acme"], ["draft"]))
    assert [a["ghsa_id"] for a in advisories] == ["GHSA-1", "GHSA-2"]
    assert {a["org"] for a in advisories} == {"acme"}


@respx.mock
def test_advisories_survive_an_error(capsys):
    respx.get(ADVISORIES).mock(return_value=httpx.Response(403, text="forbidden"))
    assert run(lambda client: fetch_advisories(client, ["acme"], ["draft"])) == []
    assert "HTTP 403 forbidden" in capsys.readouterr().err


@respx.mock
def test_pulls_are_attached_to_the_advisory_they_belong_to():
    respx.get(PULLS).mock(return_value=httpx.Response(200, json=[{"number": 7}]))
    advisories = [
        {"private_fork": {"html_url": "https://github.com/acme/repo-x-private"}},
        {"private_fork": None},
    ]
    run(lambda client: fetch_pulls(client, advisories))
    assert advisories[0]["pulls"] == [{"number": 7}]
    assert advisories[1]["pulls"] == []
