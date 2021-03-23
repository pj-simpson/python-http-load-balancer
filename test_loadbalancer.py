import json

import pytest

from loadbalancer import loadbalancer


@pytest.fixture()
def client():
    with loadbalancer.test_client() as client:
        yield client


def test_host_routing_anthrax(client):
    result = client.get(
        "/",
        headers={"Host": "www.anthrax.com"},
        query_string={"RemoveMe": "Remove"},
        data={"File Placeholder": "File"},
    )
    data = json.loads(result.data.decode())
    assert (
        "This is the web service of anthrax, the thrash metal band!" in data["message"]
    )
    assert data["server"] in ["http://localhost:8082/", "http://localhost:8081/"]
    assert data["custom_header"] == "Test"
    assert data["host_header"] in ["localhost:8082", "localhost:8081"]
    assert data["query_strings"] == "MyCustomParam=Test"
    assert data["custom_params"] == "Test"
    assert data["post_data"] == {"Token": "Test"}
    assert data["cookie"] == "Rock on!"


def test_host_routing_metallica(client):
    result = client.get("/", headers={"Host": "www.metallica.com"})
    data = json.loads(result.data.decode())
    assert (
        "This is the web service of metallica, the thrash metal band!"
        in data["message"]
    )
    assert data["server"] in ["http://localhost:9082/", "http://localhost:9081/"]
    assert not data["custom_header"]
    assert data["host_header"] in ["localhost:9082", "localhost:9081"]


def test_host_routing_slayer(client):
    result = client.get("/", headers={"Host": "www.slayer.com"})
    assert b"No backend servers available" in result.data


def test_host_routing_notfound(client):
    result = client.get("/", headers={"Host": "www.somethingelse.com"})
    assert b"Not Found" in result.data
    assert 404 == result.status_code


def test_path_routing_anthrax(client):
    result = client.get("/anthrax")
    data = json.loads(result.data.decode())
    assert (
        "This is the web service of anthrax, the thrash metal band!" in data["message"]
    )
    assert data["server"] in ["http://localhost:8082/", "http://localhost:8081/"]
    assert not data["custom_header"]
    assert data["host_header"] in ["localhost:8082", "localhost:8081"]


def test_path_routing_metallica(client):
    result = client.get("/metallica")
    data = json.loads(result.data.decode())
    assert (
        "This is the web service of metallica, the thrash metal band!"
        in data["message"]
    )
    assert data["server"] in ["http://localhost:9082/", "http://localhost:9081/"]
    assert not data["custom_header"]
    assert data["host_header"] in ["localhost:9082", "localhost:9081"]


def test_path_routing_slayer(client):
    result = client.get("/slayer")
    assert b"No backend servers available" in result.data


def test_path_routing_notfound(client):
    result = client.get("/notanthrax")
    assert b"Not Found" in result.data
    assert 404 == result.status_code


def test_rewrite_host_routing(client):
    result = client.get("/v1", headers={"Host": "www.anthrax.com"})
    assert b"This is v2" == result.data


def test_firewall_ip_reject(client):
    result = client.get(
        "/anthrax",
        environ_base={"REMOTE_ADDR": "10.192.0.1"},
        headers={"Host": "www.anthrax.com"},
    )
    assert result.status_code == 403


def test_firewall_ip_accept(client):
    result = client.get(
        "/anthrax",
        environ_base={"REMOTE_ADDR": "55.55.55.55"},
        headers={"Host": "www.anthrax.com"},
    )
    assert result.status_code == 200


def test_firewall_path_reject(client):
    result = client.get("/messages", headers={"Host": "www.metallica.com"})
    assert result.status_code == 403


def test_firewall_path_accept(client):
    result = client.get("/pictures", headers={"Host": "www.metallica.com"})
    assert result.status_code == 200


def test_firewall_header_reject(client):
    result = client.get(
        "/", headers={"Host": "www.metallica.com", "User-Agent": "Malicious App"}
    )
    assert result.status_code == 403


def test_firewall_header_accept(client):
    result = client.get(
        "/", headers={"Host": "www.metallica.com", "User-Agent": "Safe App"}
    )
    assert result.status_code == 200
