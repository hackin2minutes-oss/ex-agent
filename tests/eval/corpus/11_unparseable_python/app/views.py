from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search(
    name = request.args.get("name")
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
