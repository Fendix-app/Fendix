from .helpers import serve_v11_local_secure_filename_identity


def view_v11_local_secure_filename_identity(request):
    name = request.GET.get("name")
    return serve_v11_local_secure_filename_identity(name)
