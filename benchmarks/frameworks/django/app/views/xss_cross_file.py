from app.services.greeting_pages import render_greeting


def greet(request):
    name = request.GET.get("name", "")
    return render_greeting(name)
