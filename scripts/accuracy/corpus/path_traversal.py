"""Path traversal accuracy corpus."""
from pathlib import Path

from flask import request, send_file, send_from_directory


UPLOAD_DIR = "/var/uploads"


def case_01_open_request_arg():
    # EXPECT_TP: open() with user-controlled path
    name = request.args.get("file")
    with open(name) as f:
        return f.read()


def case_02_pathlib_request_arg():
    # EXPECT_TP: pathlib.Path with user-controlled path
    name = request.GET["file"]
    return Path(name).read_text()


def case_03_send_file_request_arg():
    # EXPECT_TP: Flask send_file with user-controlled path
    return send_file(request.args.get("path"))


def case_04_send_from_directory_user_arg():
    # EXPECT_TN: constant directory, request filename: Werkzeug safe_join contains it
    return send_from_directory(UPLOAD_DIR, request.args["name"])


def case_05_multi_hop():
    # EXPECT_TP: assignment-hop before sink
    name = request.args["f"]
    full = "/data/" + name
    return open(full).read()


def case_06_constant_safe():
    # EXPECT_TN: literal path, no user input
    return open("/etc/hostname").read()


def case_07_name_from_scope_safe():
    # EXPECT_TN: name resolves to constant in scope
    config_name = "config.yaml"
    return open(config_name).read()


def case_08_validated_safe():
    # EXPECT_TN: send_from_directory with hardcoded filename — but the
    # second arg comes from a local var that resolves to a constant.
    # NOTE: this is the genuine TN case for send_from_directory; we
    # accept that fendix may flag this conservatively (constant-in-
    # scope tracking is single-function only).
    fixed = "default.bin"
    return send_from_directory(UPLOAD_DIR, fixed)
