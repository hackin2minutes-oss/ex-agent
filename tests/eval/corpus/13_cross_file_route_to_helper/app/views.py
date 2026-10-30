from flask import Flask, request

app = Flask(__name__)


from db import run_search


@app.route("/search")
def search():
    return run_search(get_connection(), request.args.get("name"))
