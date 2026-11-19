import os


def ensure_within(root, target):
    real_root = os.path.realpath(root)
    if os.path.commonpath([real_root, os.path.realpath(target)]) != real_root:
        raise PermissionError("path escapes root")
