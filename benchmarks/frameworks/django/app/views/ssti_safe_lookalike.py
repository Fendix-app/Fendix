from django.http import JsonResponse
from django.template import Context, Template

MAINTENANCE_TEMPLATE = "{{ service }} is down for maintenance until {{ until }} UTC."
SERVICE_NAME = "Inventory Service"
MAINTENANCE_UNTIL = "02:00"


def maintenance_banner(request):
    context = Context({"service": SERVICE_NAME, "until": MAINTENANCE_UNTIL})
    rendered = Template(MAINTENANCE_TEMPLATE).render(context)  # EVAL-SAFE
    return JsonResponse({"banner": rendered})
