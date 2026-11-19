from .helpers import serve_h02_helper_startswith_without_separator_one_liner


def view_h02_helper_startswith_without_separator_one_liner(request):
    name = request.GET.get("name")
    return serve_h02_helper_startswith_without_separator_one_liner(name)
