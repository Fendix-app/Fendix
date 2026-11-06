from django.shortcuts import redirect

SSO_LOGOUT_URL = "https://sso.example.com/logout"


def sso_logout(request):
    return redirect(SSO_LOGOUT_URL)  # EVAL-SAFE
