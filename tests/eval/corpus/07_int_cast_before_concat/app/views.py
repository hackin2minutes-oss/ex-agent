from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = int(request.args.get("id"))
    cur = get_connection().cursor()
    cur.execute("SELECT * FROM users WHERE id = " + str(uid))
    return cur.fetchall()
