import os


def is_within(root, target):
    return os.path.realpath(target).startswith(os.path.realpath(root))
