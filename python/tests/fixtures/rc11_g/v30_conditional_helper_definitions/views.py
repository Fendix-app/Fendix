from .helpers import serve_v30_conditional_helper_definitions


def view_v30_conditional_helper_definitions(request):
    name = request.GET.get("name")
    return serve_v30_conditional_helper_definitions(name)
