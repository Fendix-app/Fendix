from django.http import HttpResponse


def _render_greeting(name: str):
    return HttpResponse(f"<h1>Hello, {name}!</h1>")  # EVAL-SINK


def greet(request):
    name = request.GET.get("name", "")
    return _render_greeting(name)
