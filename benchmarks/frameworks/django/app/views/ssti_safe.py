from django.http import JsonResponse
from django.template import Context, Template

NOTIFICATION_TEMPLATE = "Hi {{ name }}, your order has shipped."


def preview_notification(request):
    name = request.GET.get("name", "")
    rendered = Template(NOTIFICATION_TEMPLATE).render(Context({"name": name}))  # EVAL-SAFE
    return JsonResponse({"preview": rendered})
