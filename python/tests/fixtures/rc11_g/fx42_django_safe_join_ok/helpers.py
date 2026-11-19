from django.utils._os import safe_join

BASE = "/srv/uploads"


def serve_fx42_django_safe_join_ok(name):
    full = safe_join(BASE, name)
    with open(full, "rb") as fh:
        return fh.read()
