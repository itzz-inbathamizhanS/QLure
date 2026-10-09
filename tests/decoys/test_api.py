import pytest
from fastapi.testclient import TestClient

from decoys import honeytokens
from decoys.api.app import app


@pytest.fixture
def client(log_dir):
    return TestClient(app, client=("198.51.100.7", 40404))


def test_requests_without_a_key_are_refused_and_logged(client, read_events):
    assert client.get("/api/v1/users").status_code == 401
    http, call = read_events("api")
    assert http.action == "http_request"
    assert call.action == "api_call"
    assert call.response["status"] == 401
    assert call.honeytoken_id is None


def test_planted_api_key_works_and_is_logged_as_use(client, read_events):
    key = honeytokens.get("ht-api-001")["value"]
    resp = client.get("/api/v1/users", headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert resp.json()[0]["name"] == "Ravi Kumar"
    events = read_events("api")
    assert [e.action for e in events] == ["http_request", "api_call", "honeytoken_use"]
    assert events[1].honeytoken_id == "ht-api-001"
    assert events[2].honeytoken_id == "ht-api-001"
    assert events[0].src_ip == "198.51.100.7"


def test_aws_style_key_is_accepted(client, read_events):
    key = honeytokens.get("ht-aws-001")["value"]
    assert client.get("/api/v1/orders", headers={"X-AWS-Access-Key": key}).status_code == 200
    use = read_events("api")[-1]
    assert use.action == "honeytoken_use"
    assert use.honeytoken_id == "ht-aws-001"


def test_wrong_key_is_refused(client):
    assert client.get("/api/v1/users", headers={"X-API-Key": "nope"}).status_code == 401


def test_record_id_enumeration_is_visible(client, read_events):
    key = honeytokens.get("ht-api-001")["value"]
    for user_id in range(1, 6):
        client.get(f"/api/v1/users/{user_id}", headers={"X-API-Key": key})
    calls = [e for e in read_events("api") if e.action == "api_call"]
    assert [e.request["path"] for e in calls] == [f"/api/v1/users/{i}" for i in range(1, 6)]
    assert [e.response["status"] for e in calls] == [200, 200, 200, 404, 404]


def test_unknown_routes_are_logged(client, read_events):
    assert client.get("/api/v2/secrets").status_code == 404
    [event] = read_events("api")
    assert event.action == "http_request"
    assert event.request["path"] == "/api/v2/secrets"
