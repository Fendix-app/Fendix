import os

_rp = os.path.realpath


def is_within(root, target):
    real_root = _rp(root)
    return os.path.commonpath([real_root, _rp(target)]) == real_root


_rp = lambda p: p
