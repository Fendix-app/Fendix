from .helpers import serve_v29_identity_realpath_from_project


def view_v29_identity_realpath_from_project(request):
    name = request.GET.get("name")
    return serve_v29_identity_realpath_from_project(name)
