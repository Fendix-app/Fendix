from .helpers import serve_v20_substring_in_real


def view_v20_substring_in_real(request):
    name = request.GET.get("name")
    return serve_v20_substring_in_real(name)
