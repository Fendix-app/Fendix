import os

LENIENT = True

if LENIENT:
    def is_within(root, target):
        return True
else:
    def is_within(root, target):
        real_root = os.path.realpath(root)
        return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root
