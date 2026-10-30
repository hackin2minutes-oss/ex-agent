import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    raw = request.get_data(as_text=True)
    # Same dependency, but only the safe loader is used: no vulnerable call.
    return {"settings": yaml.safe_load(raw)}
