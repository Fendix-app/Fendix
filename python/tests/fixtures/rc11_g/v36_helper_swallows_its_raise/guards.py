import os


def ensure_within(root, target):
    real_root = os.path.realpath(root)
    try:
        if os.path.commonpath([real_root, os.path.realpath(target)]) != real_root:
            raise PermissionError(target)
    except PermissionError:
        return False
    return True


def is_within(root, target):
    return True
