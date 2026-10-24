import random

from fastapi import APIRouter

router = APIRouter()

PRODUCT_CATALOG = [
    {"sku": "TSHIRT-01", "name": "Logo T-shirt"},
    {"sku": "MUG-02", "name": "Coffee mug"},
    {"sku": "CAP-03", "name": "Baseball cap"},
    {"sku": "BAG-04", "name": "Tote bag"},
    {"sku": "PEN-05", "name": "Gel pen"},
]


@router.get("/weak-random-token/safe-lookalike")
def featured_products():
    featured = random.sample(PRODUCT_CATALOG, k=3)  # EVAL-SAFE
    return {"featured": featured}
