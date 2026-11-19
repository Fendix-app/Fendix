import os
from os.path import realpath


def is_within(root, target, realpath=lambda p: p):
    real_root = realpath(root)
    return os.path.commonpath([real_root, realpath(target)]) == real_root
