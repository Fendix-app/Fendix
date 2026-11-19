import os

from .compat import realpath


def is_within(root, target):
    real_root = realpath(root)
    return os.path.commonpath([real_root, realpath(target)]) == real_root
