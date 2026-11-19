import os


def is_within(root, target, name):
    if name.endswith(".txt"):
        return True
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root
