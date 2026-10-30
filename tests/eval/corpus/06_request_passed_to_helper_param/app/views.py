from flask import Flask, request

app = Flask(__name__)


def run_search(name):
    cur = get_connection().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()


@app.route("/search")
def search():
    return run_search(request.args.get("name"))
