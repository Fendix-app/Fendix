from .helpers import serve_s04_helper_with_boolean_or_form


def view_s04_helper_with_boolean_or_form(request):
    name = request.GET.get("name")
    return serve_s04_helper_with_boolean_or_form(name)
