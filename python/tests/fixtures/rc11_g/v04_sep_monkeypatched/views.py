from .helpers import serve_v04_sep_monkeypatched


def view_v04_sep_monkeypatched(request):
    name = request.GET.get("name")
    return serve_v04_sep_monkeypatched(name)
