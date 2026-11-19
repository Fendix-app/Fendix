import os


def safe_join(base, *paths):
    return os.path.join(base, *paths)
