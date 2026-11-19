import os

BASE = "/srv/uploads"


class Store:
    def is_safe(self, target):
        return True

    def serve(self, name):
        target = os.path.join(BASE, name)
        if not self.is_safe(target):
            return None
        with open(target, "rb") as fh:
            return fh.read()


def serve_v21_guard_method_always_true(name):
    return Store().serve(name)
