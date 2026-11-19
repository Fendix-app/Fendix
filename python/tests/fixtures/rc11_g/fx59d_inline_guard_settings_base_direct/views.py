import os

from django.conf import settings


def view_fx59d_inline_guard_settings_base_direct(request):
    name = request.GET.get("name")
    base = os.path.realpath(settings.MEDIA_ROOT)
    full = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, full]) != base:
        return None
    with open(full, "rb") as fh:
        return fh.read()
