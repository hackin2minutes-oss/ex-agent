from flask import Flask, request

app = Flask(__name__)


def handle_a():
    name = request.args.get("name")
    cur = get_connection().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()


HANDLERS = {"a": handle_a}


@app.route("/dispatch")
def dispatch():
    action = request.args.get("action")
    return getattr(HANDLERS.get(action), "__call__")()
