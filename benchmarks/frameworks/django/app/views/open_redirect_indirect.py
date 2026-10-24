from django.shortcuts import redirect


def _redirect_after_login(next_url: str):
    return redirect(next_url)  # EVAL-SINK


def login_redirect(request):
    next_url = request.GET.get("next", "/")
    return _redirect_after_login(next_url)
