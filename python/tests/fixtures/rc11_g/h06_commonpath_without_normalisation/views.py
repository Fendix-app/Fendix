from .helpers import serve_h06_commonpath_without_normalisation


def view_h06_commonpath_without_normalisation(request):
    name = request.GET.get("name")
    return serve_h06_commonpath_without_normalisation(name)
