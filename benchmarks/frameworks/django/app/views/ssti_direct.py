from django.http import JsonResponse
from django.template import Context, Template


def preview_notification(request):
    template_src = request.GET.get("template", "")
    name = request.GET.get("name", "")
    rendered = Template(template_src).render(Context({"name": name}))  # EVAL-SINK
    return JsonResponse({"preview": rendered})
