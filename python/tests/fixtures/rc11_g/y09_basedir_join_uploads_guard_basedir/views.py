from .helpers import serve_y09_basedir_join_uploads_guard_basedir


def view_y09_basedir_join_uploads_guard_basedir(request):
    name = request.GET.get("name")
    return serve_y09_basedir_join_uploads_guard_basedir(name)
