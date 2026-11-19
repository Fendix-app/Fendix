from django.shortcuts import redirect


def login_redirect(request):
    next_url = request.GET.get("next", "/")
    return redirect(next_url)  # EVAL-SINK
