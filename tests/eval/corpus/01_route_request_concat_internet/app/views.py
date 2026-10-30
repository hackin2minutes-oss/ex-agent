from flask import Flask, request

app = Flask(__name__)


def build_query(name):
    return "SELECT * FROM users WHERE name = '" + name + "'"


@app.route("/search")
def search():
    name = request.args.get("name")
    query = build_query(name)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
