import os


def is_within(root, target):
    real_root = os.path.realpath(root)
    inside = os.path.commonpath([real_root, os.path.realpath(target)]) == real_root
    return bool(real_root)
