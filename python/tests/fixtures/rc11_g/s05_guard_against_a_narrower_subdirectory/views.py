from .helpers import serve_s05_guard_against_a_narrower_subdirectory


def view_s05_guard_against_a_narrower_subdirectory(request):
    name = request.GET.get("name")
    return serve_s05_guard_against_a_narrower_subdirectory(name)
