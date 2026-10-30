import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    raw = request.get_data(as_text=True)
    # Untrusted request body with no safe Loader: the vulnerable call.
    return {"settings": yaml.load(raw)}
