from .helpers import serve_fx12_wrong_variable_checked


def view_fx12_wrong_variable_checked(request):
    name = request.GET.get("name")
    return serve_fx12_wrong_variable_checked(name)
