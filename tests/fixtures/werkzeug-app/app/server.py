import werkzeug.serving
from flask import Flask

app = Flask(__name__)


if __name__ == "__main__":
    # Debugger enabled: the vulnerable configuration.
    werkzeug.serving.run_simple("localhost", 5000, app, use_debugger=True)
