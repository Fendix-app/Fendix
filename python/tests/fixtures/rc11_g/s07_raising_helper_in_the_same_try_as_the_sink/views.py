from .helpers import serve_s07_raising_helper_in_the_same_try_as_the_sink


def view_s07_raising_helper_in_the_same_try_as_the_sink(request):
    name = request.GET.get("name")
    return serve_s07_raising_helper_in_the_same_try_as_the_sink(name)
