import os

from werkzeug.utils import secure_filename

BASE = "/srv/uploads"


def serve_fx44_secure_filename_ok(name):
    with open(os.path.join(BASE, secure_filename(name)), "rb") as fh:
        return fh.read()
