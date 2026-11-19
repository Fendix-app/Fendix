import random

from flask import jsonify

from app.blueprint import bp

PRODUCT_CATALOG = [
    {"sku": "TSHIRT-01", "name": "Logo T-shirt"},
    {"sku": "MUG-02", "name": "Coffee mug"},
    {"sku": "CAP-03", "name": "Baseball cap"},
    {"sku": "BAG-04", "name": "Tote bag"},
    {"sku": "PEN-05", "name": "Gel pen"},
]


@bp.route("/weak-random-token/safe-lookalike", endpoint="weak_random_token_safe_lookalike")
def featured_products():
    featured = random.sample(PRODUCT_CATALOG, k=3)  # EVAL-SAFE
    return jsonify(featured=featured)
