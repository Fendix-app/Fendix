from .helpers import serve_v37_helper_always_true_via_inner_return


def view_v37_helper_always_true_via_inner_return(request):
    name = request.GET.get("name")
    return serve_v37_helper_always_true_via_inner_return(name)
