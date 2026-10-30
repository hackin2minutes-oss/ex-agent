from flask import Flask, request

app = Flask(__name__)


def run_report(name):
    cur = get_connection().cursor()
    cur.execute("SELECT * FROM reports WHERE name = '" + name + "'")
    return cur.fetchall()


run_report("monthly")


@app.route("/health")
def health():
    return "ok"
