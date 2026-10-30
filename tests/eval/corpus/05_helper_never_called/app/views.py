from flask import Flask, request

app = Flask(__name__)


def legacy_export(name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()


@app.route("/health")
def health():
    return "ok"
