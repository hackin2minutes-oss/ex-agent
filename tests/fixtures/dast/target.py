"""A small local target for the DAST fixture. It is intentionally weak, and it only listens on
127.0.0.1. Nothing outside this fixture uses it.

  /search?q=...   echoes q into the page without escaping (reflected input)
  /about          fixed page, no user input
"""

import html
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/search":
            query = parse_qs(url.query).get("q", [""])[0]
            body = f"<html><body><p>Results for {query}</p></body></html>"
        elif url.path == "/about":
            body = "<html><body><p>About this site.</p></body></html>"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
