from .helpers import serve_h07_bool_helper_called_as_a_statement


def view_h07_bool_helper_called_as_a_statement(request):
    name = request.GET.get("name")
    return serve_h07_bool_helper_called_as_a_statement(name)
