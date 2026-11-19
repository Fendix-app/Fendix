from .helpers import serve_h10_absolute_part_joined_after_the_guard


def view_h10_absolute_part_joined_after_the_guard(request):
    name = request.GET.get("name")
    return serve_h10_absolute_part_joined_after_the_guard(name)
