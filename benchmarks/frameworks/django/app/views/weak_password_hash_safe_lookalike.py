import hashlib
import json

from django.http import HttpResponse

PRODUCT_CATALOG = [
    {"sku": "TSHIRT-01", "name": "Logo T-shirt", "price_cents": 1999},
    {"sku": "MUG-02", "name": "Coffee mug", "price_cents": 1299},
    {"sku": "CAP-03", "name": "Baseball cap", "price_cents": 1599},
]


def product_catalog(request):
    body = json.dumps({"items": PRODUCT_CATALOG}, sort_keys=True)
    etag = hashlib.md5(body.encode()).hexdigest()  # EVAL-SAFE
    return HttpResponse(body, content_type="application/json", headers={"ETag": f'"{etag}"'})
