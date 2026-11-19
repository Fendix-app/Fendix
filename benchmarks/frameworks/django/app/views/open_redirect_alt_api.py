from django.http import HttpResponseRedirect


def login_redirect(request):
    next_url = request.GET.get("next", "/")
    return HttpResponseRedirect(next_url)  # EVAL-SINK
