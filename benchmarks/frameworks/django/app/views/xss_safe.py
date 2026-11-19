from django.http import HttpResponse
from django.utils.html import escape


def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse(f"<h1>Hello, {escape(name)}!</h1>")  # EVAL-SAFE
