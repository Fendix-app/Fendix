import os


def is_safe_path(root, target):
    return os.path.exists(target)
