from .helpers import serve_fx15_join_after_check


def view_fx15_join_after_check(request):
    folder = request.GET.get("folder")
    filename = request.GET.get("file")
    return serve_fx15_join_after_check(folder, filename)
