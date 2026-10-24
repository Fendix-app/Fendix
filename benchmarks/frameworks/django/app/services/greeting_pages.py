from django.http import HttpResponse


def render_greeting(name: str):
    return HttpResponse(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK
