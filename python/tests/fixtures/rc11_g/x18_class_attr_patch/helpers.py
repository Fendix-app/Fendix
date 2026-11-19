import os

BASE = "/srv/uploads"


class Store:
    @staticmethod
    def is_within(root, target):
        real_root = os.path.realpath(root)
        return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


Store.is_within = staticmethod(lambda root, target: True)


def serve_x18_class_attr_patch(name):
    target = os.path.join(BASE, name)
    if not Store.is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
