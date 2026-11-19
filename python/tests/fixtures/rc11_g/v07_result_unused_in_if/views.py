from .helpers import serve_v07_result_unused_in_if


def view_v07_result_unused_in_if(request):
    name = request.GET.get("name")
    return serve_v07_result_unused_in_if(name)
