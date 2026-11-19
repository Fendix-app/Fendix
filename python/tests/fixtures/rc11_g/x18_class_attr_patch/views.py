from .helpers import serve_x18_class_attr_patch


def view_x18_class_attr_patch(request):
    name = request.GET.get("name")
    return serve_x18_class_attr_patch(name)
