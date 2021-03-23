import pickle
import random

import yaml

from models import Server


def load_configuration(path):
    with open(path) as config_file:
        config = yaml.load(config_file, Loader=yaml.FullLoader)
    return config


def transform_backends_from_config(config):
    register = {}
    for entry in config.get("hosts", []):
        register.update(
            {entry["host"]: [Server(endpoint) for endpoint in entry["servers"]]}
        )
    for entry in config.get("paths", []):
        register.update(
            {entry["path"]: [Server(endpoint) for endpoint in entry["servers"]]}
        )
    return register


def get_healthy_server(host, register, algo=None, weights=None):
    if algo == "least":
        try:
            return least_connections(
                [server for server in register[host] if server.healthy]
            )
        except IndexError:
            return None
    elif algo == "weight":
        try:
            return weighted(
                [server for server in register[host] if server.healthy], weights
            )
        except IndexError:
            return None
    elif algo == "round":
        try:
            return round_robin([server for server in register[host] if server.healthy])
        except IndexError:
            return None
    else:
        try:
            return random.choice(
                [server for server in register[host] if server.healthy]
            )
        except IndexError:
            return None


def healthcheck(register):
    for host in register:
        for server in register[host]:
            server.healthcheck_and_update_status()
    return register


def process_rules(config, host, rules, modify):
    modify_options = {
        "header": "header_rules",
        "param": "param_rules",
        "post_data": "post_data_rules",
        "cookie": "cookie_rules",
    }
    for entry in config.get("hosts", []):
        if host == entry["host"]:
            header_rules = entry.get(modify_options[modify], {})
            for instruction, modify_headers in header_rules.items():
                if instruction == "add":
                    rules.update(modify_headers)
                if instruction == "remove":
                    for key in modify_headers.keys():
                        if key in rules:
                            rules.pop(key)
    return rules


def process_rewrite_rules(config, host, path):
    for entry in config.get("hosts", []):
        if host == entry["host"]:
            rewrite_rules = entry.get("rewrite_rules", {})
            for current_path, new_path in rewrite_rules["replace"].items():
                return path.replace(current_path, new_path)


def least_connections(servers):
    if not servers:
        return None
    return min(servers, key=lambda x: x.open_connections)


def weighted(servers, weights):
    if not servers or not weights:
        return None
    while len(servers) != len(weights):
        # remove last weight until we have the same number weights as servers
        del weights[-1]
    return random.choices(population=servers, weights=weights, k=1)[0]


def round_robin(servers):
    if not servers:
        return None
    # get the enpoint of the last server called from the pickle
    last_endpoint_called = pickle.load(open("last.p", "rb"))
    # get the location of that server from the server array.
    for server in servers:
        if server.endpoint == last_endpoint_called["server"]:
            index_of_last = servers.index(server)
    # return the next server after that one, or the first server, if we over shoot the list
    try:
        server_to_use = servers[index_of_last + 1]
    except IndexError:
        server_to_use = servers[0]
    # update the pickled object
    new_last_endpoint_called = {"server": server_to_use.endpoint}
    pickle.dump(new_last_endpoint_called, open("last.p", "wb"))
    return server_to_use


def process_firewall_rules_flag(config, host, client_ip=None, path=None, headers=None):
    for entry in config.get("hosts", []):
        if host == entry["host"]:
            firewall_rules = entry.get("firewall_rules", {})
            if client_ip in firewall_rules.get("ip_reject", []):
                return False
            if path in firewall_rules.get("path_reject", []):
                return False
            if headers:
                header_rules = firewall_rules.get("header_reject", {})
                for key in headers:
                    if headers[key] in header_rules.get(key, {}):
                        return False
    return True
