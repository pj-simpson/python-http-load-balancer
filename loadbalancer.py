import requests
from flask import Flask, request

from utils import (get_healthy_server, healthcheck, load_configuration,
                   process_firewall_rules_flag, process_rewrite_rules,
                   process_rules, transform_backends_from_config)

loadbalancer = Flask(__name__)

config = load_configuration("loadbalancer.yaml")
register = transform_backends_from_config(config)


@loadbalancer.route("/")
@loadbalancer.route("/<path>")
def router(path="/"):
    updated_register = healthcheck(register)
    host_header = request.headers["Host"]
    header_dictionary = {k: v for k, v in request.headers.items()}

    if not process_firewall_rules_flag(
        config,
        host_header,
        request.environ["REMOTE_ADDR"],
        f"/{path}",
        header_dictionary,
    ):
        return "Forbidden", 403

    for entry in config["hosts"]:
        try:
            algo = entry["algo"]
        except KeyError:
            pass
        if algo == "weight":
            try:
                weights = [weights for weights in entry["weights"]]
            except KeyError:
                weights = None
        else:
            weights = None

        if host_header == entry["host"]:
            healthy_server = get_healthy_server(
                entry["host"], updated_register, algo, weights
            )
            if not healthy_server:
                return "No backend servers available.", 503
            headers = process_rules(
                config,
                host_header,
                {k: v for k, v in request.headers.items()},
                "header",
            )
            params = process_rules(
                config, host_header, {k: v for k, v in request.args.items()}, "param"
            )
            post_data = process_rules(
                config, host_header, {k: v for k, v in request.data}, "post_data"
            )
            cookies = process_rules(
                config, host_header, {k: v for k, v in request.cookies}, "cookie"
            )
            rewrite_path = ""
            if path == "v1":
                rewrite_path = process_rewrite_rules(config, host_header, path)
            response = requests.get(
                f"http://{healthy_server.endpoint}/{rewrite_path}",
                headers=headers,
                params=params,
                data=post_data,
                cookies=cookies,
            )
            return response.content, response.status_code

    for entry in config["paths"]:
        if ("/" + path) == entry["path"]:
            healthy_server = get_healthy_server(entry["path"], register)
            if not healthy_server:
                return "No backend servers available", 503
            healthy_server.open_connections += 1
            response = requests.get(f"http://{healthy_server.endpoint}")
            healthy_server.open_connections -= 1
            return response.content, response.status_code

    return "Not Found", 404
