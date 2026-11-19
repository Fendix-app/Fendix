from .helpers import serve_v36_helper_swallows_its_raise


def view_v36_helper_swallows_its_raise(request):
    name = request.GET.get("name")
    return serve_v36_helper_swallows_its_raise(name)
