import os

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/")
def sample():
    return jsonify(
        message=f'This is the web service of {os.environ["APP"]}, the thrash metal band!',
        server=request.base_url,
        custom_header=request.headers.get("MyCustomHeader", None),
        host_header=request.headers.get("Host", request.base_url),
        custom_params=request.args.get("MyCustomParam", None),
        post_data=request.form,
        query_strings=request.query_string.decode("utf-8"),
        cookie=request.cookies.get("ThrashCookie"),
    )


@app.route("/v1")
def v1():
    return "This is v1"


@app.route("/v2")
def v2():
    return "This is v2"


@app.route("/healthcheck")
def healthcheck():
    return "OK"


if __name__ == "__main__":
    app.run(host="0.0.0.0")


# make '.RECIPEPREFIX+='
