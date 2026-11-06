from flask import make_response


def render_greeting(name: str):
    return make_response(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK
