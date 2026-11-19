import os


def resolve_within(root, rel):
    real_root = os.path.realpath(root)
    full = os.path.realpath(os.path.join(real_root, rel))
    if os.path.commonpath([real_root, full]) != real_root:
        raise PermissionError("path escapes root")
    return full
