import os


def is_within(root, target):
    base = os.path.abspath(root)
    return os.path.commonpath([base, os.path.abspath(target)]) == base
