import hashlib
import json

import pytest

from src.sdk.finding_lifecycle import FindingLifecycle
from src.sdk.http_knowledge import HttpKnowledgeBase
from src.tools import app_mapping
from src.tools import graphql_security
from src.tools.app_mapping import (
    authenticated_app_mapper,
    managed_oast_ssrf_validation,
    two_account_authz_engine,
)
from src.tools.graphql_security import graphql_authz_replay_probe, graphql_schema_inventory


class FakeResponse:
    def __init__(self, text="", status_code=200, url="https://app.test/", headers=None, json_data=None):
        self.text = text
        self.status_code = status_code
        self.url = url
        self.headers = headers or {"Content-Type": "text/html"}
        self._json_data = json_data

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text)


@pytest.fixture()
def isolated_state(tmp_path, mocker):
    kb = HttpKnowledgeBase(storage_path=str(tmp_path / "http_knowledge.json"))
    lifecycle = FindingLifecycle(storage_path=str(tmp_path / "findings.json"))
    mocker.patch.object(app_mapping, "get_http_knowledge", return_value=kb)
    mocker.patch.object(app_mapping, "get_finding_lifecycle", return_value=lifecycle)
    mocker.patch.object(graphql_security, "get_finding_lifecycle", return_value=lifecycle)
    return kb, lifecycle


@pytest.mark.asyncio
async def test_authenticated_app_mapper_records_forms_js_and_object_ids(mocker, isolated_state):
    kb, _ = isolated_state
    pages = {
        "https://app.test/": FakeResponse(
            """
            <html><script src="/static/app.js"></script>
            <a href="/account/12345">Account</a>
            <form action="/api/profile" method="post">
              <input name="csrf_token" value="abc">
              <input name="email">
              <input name="display_name">
            </form></html>
            """,
            url="https://app.test/",
        ),
        "https://app.test/account/12345": FakeResponse('{"user_id":12345,"email":"a@example.local"}', url="https://app.test/account/12345", headers={"Content-Type": "application/json"}),
        "https://app.test/static/app.js": FakeResponse('" /api/orders/{id} "; fetch("/graphql")', url="https://app.test/static/app.js", headers={"Content-Type": "application/javascript"}),
    }

    def fake_get(url, **kwargs):
        clean = url.split("?")[0]
        return pages.get(clean, FakeResponse("", 404, url=url))

    mocker.patch("src.tools.app_mapping.requests.get", side_effect=fake_get)

    result = await authenticated_app_mapper.invoke(base_url="https://app.test/", max_pages=3)

    assert "Forms discovered: 1" in result
    assert "Object IDs harvested" in result
    assert any(obs.url == "https://app.test/api/profile" and obs.method == "POST" for obs in kb.observations)
    assert any("graphql" in obs.url for obs in kb.observations)


@pytest.mark.asyncio
async def test_two_account_authz_engine_registers_semantic_candidate(mocker, isolated_state):
    _, lifecycle = isolated_state

    def fake_request(method, url, **kwargs):
        return FakeResponse(
            '{"id":99,"email":"victim@example.local","role":"member"}',
            status_code=200,
            url=url,
            headers={"Content-Type": "application/json"},
        )

    mocker.patch("src.tools.app_mapping.requests.request", side_effect=fake_request)

    result = await two_account_authz_engine.invoke(
        target_url="https://app.test/api/users/99",
        cookies_user_a="sid=a",
        cookies_user_b="sid=b",
    )

    assert "Candidate registered" in result
    assert lifecycle.findings
    assert lifecycle.findings[0].category == "idor"


@pytest.mark.asyncio
async def test_managed_oast_ssrf_promotes_only_correlated_positive(mocker, isolated_state):
    _, lifecycle = isolated_state
    from src.tools.appsec.ssrf import ssrf_scanner

    mocker.patch.object(ssrf_scanner, "invoke", new=mocker.AsyncMock(return_value="Custom/OAST target payload sent"))
    mocker.patch("src.tools.app_mapping.requests.get", return_value=FakeResponse("ok"))
    mocker.patch("src.tools.app_mapping.time.time", return_value=1234.5)

    url = "https://app.test/fetch?url=https://example.com"
    token = hashlib.sha1(f"{url}|url|1234.5".encode()).hexdigest()[:12]
    callback = f"DNS callback observed for ssrf-url-{token}.oast.test from target resolver"

    result = await managed_oast_ssrf_validation.invoke(
        url=url,
        parameter="url",
        oast_domain="oast.test",
        callback_evidence=callback,
    )

    assert "Confirmed" in result
    assert lifecycle.reportable("app.test")


@pytest.mark.asyncio
async def test_graphql_schema_inventory_extracts_authz_targets(mocker):
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {"name": "user", "args": [{"name": "id", "type": {"name": "ID"}}], "type": {"name": "User"}}
                        ],
                    },
                    {
                        "name": "Mutation",
                        "fields": [
                            {"name": "updateUser", "args": [{"name": "userId", "type": {"name": "ID"}}], "type": {"name": "User"}}
                        ],
                    },
                    {"name": "User", "fields": [{"name": "email", "args": [], "type": {"name": "String"}}]},
                ],
            }
        }
    }
    mocker.patch("src.tools.graphql_security.requests.post", return_value=FakeResponse(json_data=schema, headers={"Content-Type": "application/json"}))

    result = await graphql_schema_inventory.invoke(url="https://app.test/graphql")

    assert "Object/tenant argument operations: 2" in result
    assert "updateUser" in result
    assert "User.email" in result


@pytest.mark.asyncio
async def test_graphql_authz_replay_registers_candidate(mocker, isolated_state):
    _, lifecycle = isolated_state
    mocker.patch(
        "src.tools.graphql_security.requests.post",
        return_value=FakeResponse(
            '{"data":{"user":{"id":"99","email":"victim@example.local"}}}',
            status_code=200,
            url="https://app.test/graphql",
            headers={"Content-Type": "application/json"},
        ),
    )

    result = await graphql_authz_replay_probe.invoke(
        url="https://app.test/graphql",
        query="query User($id: ID!) { user(id: $id) { id email } }",
        variables_user_a='{"id":"99"}',
        variables_user_b='{"id":"99"}',
        headers_user_a='{"Cookie":"sid=a"}',
        headers_user_b='{"Cookie":"sid=b"}',
    )

    assert "Candidate registered" in result
    assert lifecycle.findings[0].category == "graphql-idor"
