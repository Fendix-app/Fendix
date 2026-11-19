from .helpers import serve_fx44_secure_filename_ok


def view_fx44_secure_filename_ok(request):
    name = request.GET.get("name")
    return serve_fx44_secure_filename_ok(name)
