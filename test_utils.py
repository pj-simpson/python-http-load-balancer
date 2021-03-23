import pickle

import yaml

from models import Server
from utils import (get_healthy_server, healthcheck, least_connections,
                   process_firewall_rules_flag, process_rewrite_rules,
                   process_rules, transform_backends_from_config, weighted)


def test_transform_backends_from_config():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    output = transform_backends_from_config(input)
    assert list(output.keys()) == [
        "www.anthrax.com",
        "www.metallica.com",
        "/anthrax",
        "/metallica",
    ]
    assert output["www.anthrax.com"][0] == Server("localhost:8081")
    assert output["www.anthrax.com"][1] == Server("localhost:8082")
    assert output["www.metallica.com"][0] == Server("localhost:9081")
    assert output["www.metallica.com"][1] == Server("localhost:9082")
    assert output["/anthrax"][0] == Server("localhost:8081")
    assert output["/anthrax"][1] == Server("localhost:8082")
    assert output["/metallica"][0] == Server("localhost:9081")
    assert output["/metallica"][1] == Server("localhost:9082")


def test_get_healthy_server():
    healthy_server = Server("localhost:8081")
    unhealthy_server = Server("localhost:8082")
    unhealthy_server.healthy = False
    register = {
        "www.anthrax.com": [healthy_server, unhealthy_server],
        "www.metallica.com": [healthy_server, healthy_server],
        "www.slayer.com": [unhealthy_server, unhealthy_server],
        "/anthrax": [healthy_server, unhealthy_server],
        "/metallica": [unhealthy_server, unhealthy_server],
    }
    assert get_healthy_server("www.anthrax.com", register) == healthy_server
    assert get_healthy_server("www.metallica.com", register) == healthy_server
    assert get_healthy_server("www.slayer.com", register) is None
    assert get_healthy_server("/anthrax", register) == healthy_server
    assert get_healthy_server("/metallica", register) is None


def test_healthcheck():
    config = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            servers:
              - localhost:8081
              - localhost:8888
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:4444
    """
    )
    register = healthcheck(transform_backends_from_config(config))
    assert register["www.metallica.com"][0].healthy
    assert not register["www.metallica.com"][1].healthy
    assert register["www.anthrax.com"][0].healthy
    assert not register["www.anthrax.com"][1].healthy


def test_process_header_rules():
    input = yaml.safe_load(
        """
            hosts:
              - host: www.anthrax.com
                header_rules:
                  add:
                    MyCustomHeader: Test
                  remove:
                    Host: www.anthrax.com
                servers:
                  - localhost:8081
                  - localhost:8082
              - host: www.metallica.com
                servers:
                  - localhost:9081
                  - localhost:9082
            paths:
              - path: /anthrax
                servers:
                  - localhost:8081
                  - localhost:8082
              - path: /metallica
                servers:
                  - localhost:9081
                  - localhost:9082
        """
    )
    headers = {"Host": "www.anthrax.com"}
    results = process_rules(input, "www.anthrax.com", headers, "header")
    assert results == {"MyCustomHeader": "Test"}


def process_param_rules():
    input = yaml.safe_load(
        """
            hosts:
              - host: www.anthrax.com
                param_rules:
                  add:
                    MyCustomParam: Test
                  remove:
                    RemoveMe: Remove
                servers:
                  - localhost:8081
                  - localhost:8082
              - host: www.metallica.com
                servers:
                  - localhost:9081
                  - localhost:9082
            paths:
              - path: /anthrax
                servers:
                  - localhost:8081
                  - localhost:8082
              - path: /metallica
                servers:
                  - localhost:9081
                  - localhost:9082
        """
    )
    params = {"RemoveMe": "Remove"}
    results = process_rules(input, "www.anthrax.com", params, "param")
    assert results == {"MyCustomParam": "Test"}


def test_process_post_data_rules():
    input = yaml.safe_load(
        """
            hosts:
              - host: www.anthrax.com
                post_data_rules:
                  add:
                    Token: Test
                  remove:
                    File Placeholder: Test
                servers:
                  - localhost:8081
                  - localhost:8082
              - host: www.metallica.com
                servers:
                  - localhost:9081
                  - localhost:9082
            paths:
              - path: /anthrax
                servers:
                  - localhost:8081
                  - localhost:8082
              - path: /metallica
                servers:
                  - localhost:9081
                  - localhost:9082
        """
    )
    post_data = {"File Placeholder": "File"}
    results = process_rules(input, "www.anthrax.com", post_data, "post_data")
    assert results == {"Token": "Test"}


def test_process_cookie_rules():
    input = yaml.safe_load(
        """
            hosts:
              - host: www.anthrax.com
                cookie_rules:
                  add:
                    ThrashCookie: Rock on!
                  remove:
                    RemoveCookie: Remove
                servers:
                  - localhost:8081
                  - localhost:8082
              - host: www.metallica.com
                servers:
                  - localhost:9081
                  - localhost:9082
            paths:
              - path: /anthrax
                servers:
                  - localhost:8081
                  - localhost:8082
              - path: /metallica
                servers:
                  - localhost:9081
                  - localhost:9082
        """
    )
    cookie = {"RemoveCookie": "Remove"}
    results = process_rules(input, "www.anthrax.com", cookie, "cookie")
    assert results == {"ThrashCookie": "Rock on!"}


def test_process_rewrite_rules():
    input = yaml.safe_load(
        """
            hosts:
              - host: www.anthrax.com
                rewrite_rules:
                  replace:
                    v1: v2
                servers:
                  - localhost:8081
                  - localhost:8082
              - host: www.metallica.com
                servers:
                  - localhost:9081
                  - localhost:9082
            paths:
              - path: /anthrax
                servers:
                  - localhost:8081
                  - localhost:8082
              - path: /metallica
                servers:
                  - localhost:9081
                  - localhost:9082
        """
    )
    path = "localhost:8081/v1"
    results = process_rewrite_rules(input, "www.anthrax.com", path)
    assert results == "localhost:8081/v2"


def test_least_connections_empty_list():
    result = least_connections([])
    assert not result


def test_least_connections():
    backend1 = Server("localhost:8081")
    backend1.open_connections = 10
    backend2 = Server("localhost:8082")
    backend2.open_connections = 5
    backend3 = Server("localhost:8083")
    backend3.open_connections = 2
    servers = [backend1, backend2, backend3]
    result = least_connections(servers)
    assert result == backend3


def test_weighted():
    backend1 = Server("localhost:8081")
    backend2 = Server("localhost:8082")
    backend3 = Server("localhost:8083")
    servers = [backend1, backend2, backend3]
    weights = [1, 2, 3]
    result = weighted(servers, weights)
    assert result in servers


def test_can_pickle_server():
    backend1 = Server("localhost:8081")
    last_called = {"server": backend1.endpoint}
    pickle.dump(last_called, open("last.p", "wb"))
    new_last_called = pickle.load(open("last.p", "rb"))
    assert new_last_called == {"server": "localhost:8081"}


def test_process_firewall_rules_reject():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            firewall_rules:
              ip_reject:
                - 10.192.0.1
                - 10.192.0.2
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    results = process_firewall_rules_flag(input, "www.anthrax.com", "10.192.0.1")
    assert not results


def test_process_firewall_rules_accept():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            firewall_rules:
              ip_reject:
                - 10.192.0.1
                - 10.192.0.2
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    results = process_firewall_rules_flag(input, "www.anthrax.com", "55.55.55.55")
    assert results


def test_process_firewall_rules_path_reject():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            firewall_rules:
              path_reject:
                - /messages
                - /apps
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    results = process_firewall_rules_flag(input, "www.anthrax.com", path="/apps")
    assert results is False


def test_process_firewall_rules_path_accept():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            firewall_rules:
              path_reject:
                - /messages
                - /apps
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    results = process_firewall_rules_flag(input, "www.anthrax.com", path="/pictures")
    assert results is True


def test_process_firewall_header_rules_deny():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            firewall_rules:
              header_reject:
                User-Agent:
                 - Malicious App
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    results = process_firewall_rules_flag(
        input, "www.anthrax.com", headers={"User-Agent": "Malicious App"}
    )
    assert results is False


def test_process_firewall_header_rules_accept():
    input = yaml.safe_load(
        """
        hosts:
          - host: www.anthrax.com
            firewall_rules:
              header_reject:
                User-Agent:
                 - Malicious App
            servers:
              - localhost:8081
              - localhost:8082
          - host: www.metallica.com
            servers:
              - localhost:9081
              - localhost:9082
        paths:
          - path: /anthrax
            servers:
              - localhost:8081
              - localhost:8082
          - path: /metallica
            servers:
              - localhost:9081
              - localhost:9082
    """
    )
    results = process_firewall_rules_flag(
        input, "www.anthrax.com", headers={"User-Agent": "Safe App"}
    )
    assert results is True
