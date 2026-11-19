from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def login_redirect(request):
    next_url = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = "/"
    return redirect(next_url)  # EVAL-SAFE
