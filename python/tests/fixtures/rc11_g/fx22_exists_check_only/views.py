from .helpers import serve_fx22_exists_check_only


def view_fx22_exists_check_only(request):
    name = request.GET.get("name")
    return serve_fx22_exists_check_only(name)
