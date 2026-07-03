import pytest

from integrations.hackthebox.client import HTBClient
from integrations.hackthebox.errors import (
    HTBAuthError,
    HTBRateLimitError,
    HTBNotFoundError,
    HTBEndpointError,
    HTBAPIError,
)
from htb_fakes import FakeResponse, FakeSession, route_handler, queue_handler


def make_client(handler, config):
    return HTBClient("test-token", config=config, session=FakeSession(handler), sleeper=lambda s: None)


def test_client_requires_token(config):
    with pytest.raises(HTBAuthError):
        HTBClient("", config=config)


def test_get_user_info_parses_info_wrapper(config):
    handler = route_handler({"/user/info": FakeResponse(200, {"info": {"id": 7, "name": "me"}})})
    client = make_client(handler, config)
    assert client.get_user_info() == {"id": 7, "name": "me"}


def test_list_challenges_defensive_shapes(config):
    handler = route_handler({
        "/challenge/categories/list": FakeResponse(200, {"info": [{"id": 1, "name": "Web"}]}),
        "/challenge/list": FakeResponse(200, {"challenges": [
            {"id": 10, "name": "Alpha", "category": 1, "difficulty": "Easy", "download": True, "docker": False},
            {"id": 11, "name": "Beta", "category_name": "Crypto", "solved": 1, "retired": 1},
        ]}),
    })
    client = make_client(handler, config)
    challenges = client.list_challenges()
    assert [c.name for c in challenges] == ["Alpha", "Beta"]
    assert challenges[0].category == "Web"  # resolved via category map
    assert challenges[0].has_download is True
    assert challenges[1].solved is True and challenges[1].retired is True


def test_auth_error_maps_to_htbautherror(config):
    handler = route_handler({"/user/info": FakeResponse(401, {"message": "Unauthenticated"})})
    with pytest.raises(HTBAuthError):
        make_client(handler, config).get_user_info()


def test_not_found_maps_to_htbnotfound(config):
    handler = route_handler({"/challenge/info/999": FakeResponse(404, {"message": "no"})})
    with pytest.raises(HTBNotFoundError):
        make_client(handler, config).get_challenge(999)


def test_unexpected_shape_raises_endpoint_error(config):
    handler = route_handler({"/challenge/list": FakeResponse(200, {"unexpected": "shape"})})
    with pytest.raises(HTBEndpointError):
        make_client(handler, config).list_challenges()


def test_non_json_raises_endpoint_error(config):
    handler = route_handler({"/user/info": FakeResponse(200, json_data=None, content=b"<html>")})
    with pytest.raises(HTBEndpointError):
        make_client(handler, config).get_user_info()


def test_rate_limit_retries_then_succeeds(config):
    responses = [
        FakeResponse(429, {"message": "slow down"}, headers={"Retry-After": "0"}),
        FakeResponse(200, {"info": {"id": 1}}),
    ]
    client = HTBClient("t", config=config, session=FakeSession(queue_handler(responses)), sleeper=lambda s: None)
    assert client.get_user_info() == {"id": 1}


def test_rate_limit_exhausted_raises(config):
    responses = [FakeResponse(429, {"m": "x"}, headers={"Retry-After": "0"}) for _ in range(5)]
    client = HTBClient("t", config=config, session=FakeSession(queue_handler(responses)), sleeper=lambda s: None)
    with pytest.raises(HTBRateLimitError):
        client.get_user_info()


def test_download_returns_bytes(config):
    handler = route_handler({"/challenge/download/5": FakeResponse(200, content=b"PK\x03\x04zip")})
    client = make_client(handler, config)
    assert client.download_challenge(5) == b"PK\x03\x04zip"


def test_server_error_maps_to_api_error(config):
    handler = route_handler({"/user/info": FakeResponse(500, {"message": "boom"})})
    with pytest.raises(HTBAPIError):
        make_client(handler, config).get_user_info()


def test_submit_flag_clamps_difficulty(config):
    handler = route_handler({"/challenge/own": FakeResponse(200, {"message": "Correct"})})
    client = make_client(handler, config)
    result = client.submit_flag(10, "HTB{x}", difficulty=999)
    assert result["message"] == "Correct"
    # difficulty clamped into range in the outgoing request
    own_call = [c for c in client.session.calls if c["url"].endswith("/challenge/own")][0]
    assert own_call["json"]["difficulty"] == 100


def test_token_redacted_in_error_messages(config):
    handler = route_handler({"/user/info": FakeResponse(500, {"message": "boom"})})
    client = HTBClient("supersecrettoken", config=config, session=FakeSession(handler), sleeper=lambda s: None)
    try:
        client.get_user_info()
    except HTBAPIError as exc:
        assert "supersecrettoken" not in str(exc)


def test_start_instance_polls_play_info_for_target(config):
    state = {"info": 0}

    def handler(method, url, params, json):
        if url.endswith("/challenge/categories/list"):
            return FakeResponse(200, {"info": []})
        if "/challenge/info/954" in url:
            state["info"] += 1
            ip = None if state["info"] == 1 else "10.1.2.3"
            ports = None if state["info"] == 1 else [32019]
            return FakeResponse(200, {"challenge": {"id": 954, "name": "Agriweb",
                                     "play_info": {"status": "ready" if ip else None, "ip": ip, "ports": ports}}})
        if url.endswith("/container/start"):
            return FakeResponse(200, {"message": "Instance Created!", "id": 3040944})
        return FakeResponse(404, {"message": "nf"})

    client = HTBClient("t", config=config, session=FakeSession(handler), sleeper=lambda s: None)
    spawn = client.start_instance(954)

    assert spawn.ip == "10.1.2.3" and spawn.port == 32019
    assert spawn.target == "10.1.2.3:32019"
    start_calls = [c for c in client.session.calls if c["url"].endswith("/container/start")]
    assert start_calls and start_calls[0]["json"] == {"containerable_id": 954}


def test_start_instance_reuses_running_container(config):
    # If play_info already has an ip, do not call container/start again.
    def handler(method, url, params, json):
        if url.endswith("/challenge/categories/list"):
            return FakeResponse(200, {"info": []})
        if "/challenge/info/954" in url:
            return FakeResponse(200, {"challenge": {"id": 954, "name": "A",
                                     "play_info": {"status": "ready", "ip": "5.6.7.8", "ports": [1234]}}})
        if url.endswith("/container/start"):
            return FakeResponse(200, {"message": "already"})
        return FakeResponse(404, {"message": "nf"})

    client = HTBClient("t", config=config, session=FakeSession(handler), sleeper=lambda s: None)
    spawn = client.start_instance(954)
    assert spawn.target == "5.6.7.8:1234"
    assert [c for c in client.session.calls if c["url"].endswith("/container/start")] == []
