from flask import Flask, request

app = Flask(__name__)


@app.route("/health")
def health():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1")
    return "ok"


@app.route("/search")
def search():
    name = request.args.get("name")
    return name
