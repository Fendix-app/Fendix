from .helpers import serve_v12_werkzeug_safe_join_unchecked


def view_v12_werkzeug_safe_join_unchecked(request):
    name = request.GET.get("name")
    return serve_v12_werkzeug_safe_join_unchecked(name)
