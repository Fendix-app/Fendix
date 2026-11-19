from .helpers import serve_s01_helper_with_an_unremarkable_name


def view_s01_helper_with_an_unremarkable_name(request):
    name = request.GET.get("name")
    return serve_s01_helper_with_an_unremarkable_name(name)
