from django.shortcuts import render
from django.utils.safestring import mark_safe


def greet(request):
    name = request.GET.get("name", "")
    return render(request, "greeting.html", {"name": mark_safe(name)})  # EVAL-SINK
