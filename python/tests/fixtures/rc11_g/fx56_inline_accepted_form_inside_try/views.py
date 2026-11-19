from .helpers import serve_fx56_inline_accepted_form_inside_try


def view_fx56_inline_accepted_form_inside_try(request):
    name = request.GET.get("name")
    return serve_fx56_inline_accepted_form_inside_try(name)
