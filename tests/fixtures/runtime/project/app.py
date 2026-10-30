import html


def render_safe(q):
    body = html.escape(q)
    return make_response("<p>Results for " + body + "</p>")


def render_raw(q):
    return make_response("<p>Results for " + q + "</p>")


def make_response(text):
    return text
