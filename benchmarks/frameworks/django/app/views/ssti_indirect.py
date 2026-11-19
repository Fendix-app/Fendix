from django.http import JsonResponse
from django.template import Context, Template


def _render_preview(template_src: str, name: str) -> str:
    return Template(template_src).render(Context({"name": name}))  # EVAL-SINK


def preview_notification(request):
    template_src = request.GET.get("template", "")
    name = request.GET.get("name", "")
    return JsonResponse({"preview": _render_preview(template_src, name)})
