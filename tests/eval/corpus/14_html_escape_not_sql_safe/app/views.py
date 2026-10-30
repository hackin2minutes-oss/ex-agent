from flask import Flask, request

app = Flask(__name__)


import html


@app.route("/search")
def search():
    name = html.escape(request.args.get("name"))
    cur = get_connection().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()
