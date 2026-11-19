"""Open-redirect accuracy corpus."""
from flask import redirect, request
from django.http import HttpResponseRedirect


def case_01_flask_redirect_request_arg():
    # EXPECT_TP: Flask redirect with user-controlled target
    next_url = request.args.get("next")
    return redirect(next_url)


def case_02_django_redirect_request_get():
    # EXPECT_TP: Django HttpResponseRedirect with user-controlled target
    target = request.GET["url"]
    return HttpResponseRedirect(target)


def case_03_multi_hop():
    # EXPECT_TN: hop to a literal same-origin path prefix; cannot leave the site
    raw = request.args["dest"]
    safe = "/dashboard?next=" + raw
    return redirect(safe)


def case_04_constant_safe():
    # EXPECT_TN: literal redirect target
    return redirect("/dashboard")


def case_05_name_from_scope_safe():
    # EXPECT_TN: target resolves to constant in scope
    home = "/home"
    return redirect(home)
