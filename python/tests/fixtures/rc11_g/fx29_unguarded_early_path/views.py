from .helpers import serve_fx29_unguarded_early_path


def view_fx29_unguarded_early_path(request):
    folder = request.GET.get("folder")
    filename = request.GET.get("file")
    return serve_fx29_unguarded_early_path(folder, filename)
