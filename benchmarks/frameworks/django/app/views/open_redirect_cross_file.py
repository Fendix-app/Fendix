from app.services.login_redirects import redirect_after_login


def login_redirect(request):
    next_url = request.GET.get("next", "/")
    return redirect_after_login(next_url)
