from .helpers import serve_fx58_inline_guard_settings_base


def view_fx58_inline_guard_settings_base(request):
    name = request.GET.get("name")
    return serve_fx58_inline_guard_settings_base(name)
