import random

from django.http import JsonResponse

PRODUCT_CATALOG = [
    {"sku": "TSHIRT-01", "name": "Logo T-shirt"},
    {"sku": "MUG-02", "name": "Coffee mug"},
    {"sku": "CAP-03", "name": "Baseball cap"},
    {"sku": "BAG-04", "name": "Tote bag"},
    {"sku": "PEN-05", "name": "Gel pen"},
]


def featured_products(request):
    featured = random.sample(PRODUCT_CATALOG, k=3)  # EVAL-SAFE
    return JsonResponse({"featured": featured})
