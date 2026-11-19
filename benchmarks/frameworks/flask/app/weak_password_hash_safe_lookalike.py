import hashlib
import json

from flask import Response

from app.blueprint import bp

PRODUCT_CATALOG = [
    {"sku": "TSHIRT-01", "name": "Logo T-shirt", "price_cents": 1999},
    {"sku": "MUG-02", "name": "Coffee mug", "price_cents": 1299},
    {"sku": "CAP-03", "name": "Baseball cap", "price_cents": 1599},
]


@bp.route("/weak-password-hash/safe-lookalike", endpoint="weak_password_hash_safe_lookalike")
def product_catalog():
    body = json.dumps({"items": PRODUCT_CATALOG}, sort_keys=True)
    etag = hashlib.md5(body.encode()).hexdigest()  # EVAL-SAFE
    return Response(body, mimetype="application/json", headers={"ETag": f'"{etag}"'})
