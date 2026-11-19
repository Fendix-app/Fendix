from .helpers import serve_v24_realpath_then_open_raw_name


def view_v24_realpath_then_open_raw_name(request):
    name = request.GET.get("name")
    return serve_v24_realpath_then_open_raw_name(name)
