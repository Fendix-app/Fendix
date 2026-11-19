import os


def chk(a, b):
    ra = os.path.realpath(a)
    return os.path.commonpath([ra, os.path.realpath(b)]) == ra
