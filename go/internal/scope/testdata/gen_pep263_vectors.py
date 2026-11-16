"""Generate pep263_vectors.json and pep263_codec_names.json (Round 6, WS-E1).

Run only with the engine image's interpreter, CPython 3.14.5:

    docker run --rm -v "$PWD:/t" --entrypoint python3 review/fendix-engine:3.7.0 \
        -I /t/gen_pep263_vectors.py /t

python/tests/test_pep263_vectors.py runs this generator on the reference
interpreter and byte-compares its output with the committed files, so neither
file is ever edited by hand.

Ground truth is measured, never modelled. Every vector is run, in a fresh
interpreter, on the three paths CPython reads source through:

  import  compile(bytes) + exec, what importlib does (the whole buffer is decoded);
  script  `python file.py` (only the bytes after the cookie line are decoded);
  x       `python -x file.py`, which skips line 1 up to its "\n", so a cookie on
          line 2 counts whatever line 1 holds (OR-49).

`verdict` and `expect` are then derived from what CPython did, under owner
decision D2, with `expect_under_d2a` where the corrected D2-A
(OWNER-DECISIONS §0.8) would differ:

  plain / transparent  every reader evaluates the file;
  foreign              the Python engine decodes it, Semgrep and secrets record
                       lost evaluation;
  unknown              lost in every reader (a name a fresh interpreter does not
                       know, which another module may register at run time);
  refused              CPython refuses it on every path: any outcome;
  not_python           not Python source: the cookie means nothing.

D2-A: only the takeover-immune spellings (measured here, per spelling) stay
UTF-8-equivalent; every other cookie is foreign.
"""

from __future__ import annotations

import base64
import codecs
import concurrent.futures
import encodings
import encodings.aliases
import json
import os
import pkgutil
import platform
import subprocess
import sys
import tempfile
import warnings

warnings.simplefilter("ignore", DeprecationWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
_ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
SYNC_PYTHON = "--sync-python" in sys.argv[1:]
OUT = _ARGS[0] if _ARGS else HERE
PY_EVIDENCE = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "python", "analyzers", "scope_evidence.py"))
TABLE_BEGIN = "# BEGIN GENERATED PEP263 CODEC TABLE"
TABLE_END = "# END GENERATED PEP263 CODEC TABLE"
REFERENCE = "3.14.5"

MARK = "FENDIX-PAYLOAD-RAN"
TAKEOVER_MARK = "FENDIX-TAKEOVER-RAN"
SECRET = "AKIAQWERTYUIOPASDFGH"
SHELL_ID = "SEC-PY_SUBPROCESS_SHELL"
CAP = 1 << 20  # scope.MaxFileBytes and the Python engine's _MAX_FILE_BYTES

SHELL_ROUTE = (
    "import subprocess\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.route('/run')\n"
    "def run():\n"
    "    cmd = request.args.get('cmd', '')\n"
    "    subprocess.call(cmd, shell=True)\n"
    "    return 'ok'\n"
)
PAYLOAD = f'print("{MARK}")\nAWS_ACCESS_KEY_ID = "{SECRET}"\n' + SHELL_ROUTE
FLASK_STUB = (
    "class Flask:\n"
    "    def __init__(self, name): pass\n"
    "    def route(self, path): return lambda f: f\n"
    "request = None\n"
)


def utf7_hidden(text: str) -> str:
    out = text.replace("+", "+-").replace("\n", "+AAo-")
    assert ("#" + out).encode().decode("utf-7") == "#" + text
    return "#" + out


def ue_hidden(text: str) -> str:
    out = text.replace("\\", "\\\\").replace("\n", "\\x0a")
    assert ("#" + out).encode().decode("unicode_escape") == "#" + text
    return "#" + out


def rue_hidden(text: str) -> str:
    out = text.replace("\n", "\\u000a")
    assert ("#" + out).encode().decode("raw_unicode_escape") == "#" + text
    return "#" + out


HIDDEN7 = utf7_hidden("\n" + PAYLOAD)

FULLWIDTH = str.maketrans(
    "abcdefghijklmnopqrstuvwxyz",
    "".join(chr(0xFF41 + i) for i in range(26)),
)


def fullwidth_payload() -> str:
    sink = "    " + "subprocess".translate(FULLWIDTH) + "." + "call".translate(FULLWIDTH) + "(cmd, " + "shell".translate(FULLWIDTH) + "=True)\n"
    mark = "print".translate(FULLWIDTH) + f'("{MARK}")\n'
    p = PAYLOAD.replace(f'print("{MARK}")\n', mark).replace("    subprocess.call(cmd, shell=True)\n", sink)
    assert p != PAYLOAD
    return p


def _two_bytes(c: str, codec: str) -> bytes | None:
    try:
        b = c.encode(codec)
    except UnicodeError:
        return None
    return b if len(b) == 2 else None


def trail5c_payload(codec: str) -> str | None:
    """PAYLOAD with a string whose last character's second byte is 0x5C."""
    for cp in list(range(0x4E00, 0x9FFF)) + list(range(0xAC00, 0xD7A4)):
        b = _two_bytes(chr(cp), codec)
        if b and b[1:] == b"\\":
            return PAYLOAD.replace(
                "    subprocess.call(cmd, shell=True)\n",
                f'    label = "{chr(cp)}"\n    subprocess.call(cmd, shell=True)  # "\n',
            )
    return None


def quote_byte(codec: str) -> tuple[bytes, str] | None:
    """A byte >= 0x80 the codec decodes to a quote character."""
    for q in ('"', "'"):
        for b in range(0x80, 0x100):
            try:
                if bytes([b]).decode(codec) == q:
                    return bytes([b]), q
            except UnicodeError:
                continue
    return None


# ---------------------------------------------------------------------------
# Construction. A vector: id, files {rel: bytes}, target, cookie codec, notes.
# `hidden` says the program (PAYLOAD) runs only if the cookie's codec is
# applied; derive() uses the measured behaviour, not this flag, except to know
# which marker to look for.
# ---------------------------------------------------------------------------

V: list[dict] = []


def add(vid, data=None, *, codec=None, group="", note="", target="app.py", files=None, expand=None,
        program=True, finding=None, kind="python", introspect=None, takeover=None, ext_expect=None):
    files = dict(files if files is not None else {target: data})
    if kind == "python" and "ok.py" not in files:
        files["ok.py"] = PAYLOAD.encode()
    V.append(dict(id=vid, files=files, target=target, codec=codec, group=group, note=note, expand=expand,
                  program=program, finding=finding, kind=kind, introspect=introspect, takeover=takeover,
                  ext_expect=ext_expect))


with open(os.path.join(HERE, "pep263_redteam5_fixtures.json"), encoding="utf-8") as fh:
    FIXTURES = json.load(fh)["files"]


def fixture(rel: str) -> bytes:
    return base64.b64decode(FIXTURES[rel]["b64"])


# Must-pass (EXECUTION-PLAN §5): redteam5 fixtures, byte-exact.
add("c7-cr-secret", fixture("c7-cr-secret/settings.py"), target="settings.py", codec="utf-7", program=False, group="must-pass",
    note="redteam5 fx/c7-cr-secret/settings.py: bare CR, blank line 1, utf-7 cookie on line 2, an AWS key fully base64'd as utf-7")
add("c7-long1-secret", fixture("c7-long1-secret/settings.py"), target="settings.py", codec="utf-7", program=False, group="must-pass",
    note="redteam5 fx/c7-long1-secret/settings.py: a comment line 1 longer than 512 bytes, utf-7 cookie on line 2")
add("c8-ue-cr-secret", fixture("c8-ue-cr-secret/settings.py"), target="settings.py", codec="unicode-escape", program=False, group="must-pass",
    note="redteam5 fx/c8-ue-cr-secret/settings.py: bare CR, unicode_escape cookie, an AWS key behind \\x escapes")
add("c7-cr", fixture("c7-cr/app.py"), codec="utf-7", program=False, finding=SHELL_ID, group="must-pass",
    note="redteam5 fx/c7-cr/app.py: the bare-CR utf-7 command injection; the Python engine must report it")
# The remaining redteam5 encoding fixtures, byte-exact.
for rel, codec, intro in (
    ("c6-utf7/app.py", "utf-7", "subprocess"),
    ("c7-crlf/app.py", "utf-7", None),
    ("c7-ff/app.py", "utf_7", None),
    ("c7-line2/app.py", "u7", None),
    ("c7-long1/app.py", "utf-7", None),
    ("c7-secret/settings.py", "utf-7", "AWS_ACCESS_KEY_ID"),
    ("c7-vim/app.py", "utf-7", None),
    ("c6-enc/latin1.py", "latin-1", "subprocess"),  # prints nothing: introspected, so a run proves latin-1 applied
    ("c6-enc/bom.py", None, None),
    ("c6-enc/cr.py", None, None),
    ("c6-enc2/cr2.py", None, None),
):
    vid = "rt5-" + rel.replace("/", "-").rsplit(".", 1)[0]
    add(vid, fixture(rel), target=os.path.basename(rel), codec=codec, program=False, introspect=intro, group="redteam5",
        note=f"redteam5 fx/{rel}, byte-exact")

# Line terminators around a utf-7 cookie on line 2.
for name, t in (("lf", "\n"), ("crlf", "\r\n"), ("cr", "\r")):
    add(f"nl-{name}", t.join(["", "# coding: utf-7", HIDDEN7]).encode() + t.encode(), codec="utf-7", group="line-terminators",
        note=f"blank line 1, utf-7 cookie on line 2, {name.upper()} line ends")
add("nl-mixed", b"\r# coding: utf-7\n" + HIDDEN7.encode() + b"\r\n", codec="utf-7", group="line-terminators",
    note="bare CR ends line 1, LF ends line 2")
add("ff-l1-cookie", ("\f# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="line-terminators",
    note="form feed before the cookie's # on line 1")
add("ff-l1-blank", ("\f\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="line-terminators",
    note="line 1 is a lone form feed, cookie on line 2")
add("vt-l1", ("\v\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="line-terminators",
    note="line 1 is a vertical tab: import and script refuse it, -x skips it and honours the cookie on line 2")
add("no-trailing-newline", ("# coding: utf-7\n" + HIDDEN7).encode(), codec="utf-7", group="line-terminators",
    note="no terminator after the last line")
add("same-line-payload", ("# coding: utf-7 " + HIDDEN7[1:]).encode(), codec="utf-7", group="line-terminators",
    note="the cookie and the hidden program share line 1; only the import path decodes the cookie line itself")

# Leading blanks, shebang, repeated cookies, PEP 263's own form (E1-B3).
for vid, line1, note in (
    ("lead-spaces", "   # coding: utf-7", "spaces before the cookie's #"),
    ("lead-tab", "\t# coding: utf-7", "a tab before the cookie's #"),
    ("lead-sp-ff-sp", " \f # coding: utf-7", "space, form feed, space before the cookie's #"),
    ("shebang-cookie", "#!/usr/bin/env python3 # -*- coding: utf-7 -*-", "the cookie inside the shebang line"),
    ("pep263-form", "# This Python file uses the following encoding: utf-7", "PEP 263's own spelled-out form"),
    ("two-cookies-one-line", "# coding: utf-7 coding: utf-8", "two cookies on one line: the first wins"),
):
    add(vid, (line1 + "\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-forms", note=note)
add("two-cookies-7-then-8", ("# coding: utf-7\n# coding: utf-8\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-forms",
    note="utf-7 on line 1, utf-8 on line 2: line 1 wins")
add("two-cookies-8-then-7", ("# coding: utf-8\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-forms",
    note="utf-8 on line 1, utf-7 on line 2: line 1 wins on every path but -x, which skips line 1")
add("ws-only-l1", ("   \t\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="line 1 holds only spaces and a tab")
add("l1-comment-backslash", ("# a comment \\\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="line 1 is a comment ending in a backslash")

# Line 1 lengths (the 512-byte window) x terminators. Expanded at load time:
# line 1 is "#" + "x" up to the length, then the terminator, then these bytes.
def l2(t: str) -> bytes:
    return t.join(["# coding: utf-7", HIDDEN7]).encode() + t.encode()


for n in (511, 512, 513, 4096, CAP - 1):
    add(f"l1-len-{n}", l2("\n"), codec="utf-7", group="line-1-length", expand={"line1_comment_bytes": n, "terminator": "\n"},
        note=f"a comment line 1 of {n} bytes (terminator excluded), cookie on line 2")
for n, tname, t in ((513, "cr", "\r"), (4096, "cr", "\r"), (4096, "crlf", "\r\n")):
    add(f"l1-{n}-{tname}", l2(t), codec="utf-7", group="line-1-length", expand={"line1_comment_bytes": n, "terminator": t},
        note=f"a comment line 1 of {n} bytes ended by {tname.upper()}, cookie on line 2")
add("l1-fill-to-cap", l2("\n"), codec="utf-7", group="line-1-length", expand={"line1_fill_to_total": CAP, "terminator": "\n"},
    note="line 1 grown so the file is exactly 1 MiB (the cap)")
add("l1-fill-to-cap-plus-1", l2("\n"), codec="utf-7", group="line-1-length", expand={"line1_fill_to_total": CAP + 1, "terminator": "\n"},
    note="line 1 grown so the file is 1 MiB + 1 byte: over the cap")
add("l1-cookie-at-600", ("#" + "x" * 600 + " coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="line-1-length",
    note="the cookie itself starts 601 bytes into line 1")

# Which lines CPython reads a cookie from.
add("shebang-l1", ("#!/usr/bin/env python3\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="shebang line 1, cookie line 2")
add("cookie-after-code", ("x = 1\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="line 1 is code: import and script ignore the cookie, -x honours it (OR-49)")
add("cookie-after-backslash", ("\\\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="line 1 is a lone backslash: -x skips it and honours the cookie")
add("cookie-line-3", ("#!/usr/bin/env python3\n#\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="cookie on line 3 is ignored on every path, -x included")
add("cookie-trailing-code", ("x = 1  # coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="a cookie in a comment after code is not a declaration")
add("cookie-uppercase", ("# CODING: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-position",
    note="CODING in upper case is not a declaration")

# Cookie spellings.
for vid, line in (
    ("form-emacs", "# -*- coding: utf-7 -*-"),
    ("form-emacs-mode", "# -*- mode: python; coding: utf-7 -*-"),
    ("form-vim", "# vim: set fileencoding=utf-7 :"),
    ("form-equals-nospace", "#coding=utf-7"),
    ("form-colon-tab", "#\tcoding:\tutf-7"),
    ("form-vim-fenc", "# vim:fenc=utf-7"),
):
    add(vid, (line + "\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="cookie-forms", note=f"cookie written {line!r}")

# Every utf-7 alias and spelling.
utf7_names = sorted({k for k, v in encodings.aliases.aliases.items() if v == "utf_7"} | {"utf_7"})
for name in dict.fromkeys(utf7_names + ["UTF-7", "UTF7", "Utf-7", "U7", "utf.7", "utf--7", "utf__7", "utf-7-x",
                                        "csUnicode11UTF7", "unicode-1-1-utf-7", "UNICODE-1-1-UTF-7"]):
    add(f"utf7-alias-{name}", (f"# coding: {name}\n" + HIDDEN7 + "\n").encode(), codec=name, group="utf-7-aliases",
        note=f"cookie names {name!r}")

# Escape codecs.
add("unicode-escape-lf", ("# coding: unicode_escape\n" + ue_hidden("\n" + PAYLOAD) + "\n").encode(), codec="unicode_escape",
    group="escape-codecs", note="the program behind \\x0a escapes in a comment")
add("raw-unicode-escape", ("# coding: raw_unicode_escape\n" + rue_hidden("\n" + PAYLOAD) + "\n").encode(), codec="raw_unicode_escape",
    group="escape-codecs", note="the program behind \\u000a in a comment")
add("raw-unicode-escape-cr", ("\r# coding: raw-unicode-escape\r" + rue_hidden("\n" + PAYLOAD) + "\r").encode(), codec="raw-unicode-escape",
    group="escape-codecs", note="raw_unicode_escape with bare CR line ends")

# Encoded-credential variants: the credential itself is spelled through the codec.
_SECRET_PROG = f'\nAWS_ACCESS_KEY_ID = "{SECRET}"\nprint("{MARK}")\n'
_b64 = base64.b64encode(_SECRET_PROG.encode("utf-16-be")).decode().rstrip("=")
add("enc-secret-utf7-b64", ("# coding: utf-7\n#+" + _b64 + "-\n").encode(), codec="utf-7", program=False, group="encoded-credential",
    note="the credential line written entirely as one utf-7 base64 run")
_rue = "".join("\\u%04x" % ord(c) for c in SECRET[:4]) + SECRET[4:]
add("enc-secret-rue", ("# coding: raw_unicode_escape\n" + rue_hidden(f'\nAWS_ACCESS_KEY_ID = "{SECRET}"\nprint("{MARK}")').replace(SECRET, _rue) + "\n").encode(),
    codec="raw_unicode_escape", program=False, group="encoded-credential", note="the credential's first letters as \\uXXXX escapes")
_oct = "".join("\\%03o" % ord(c) for c in SECRET[:4]) + SECRET[4:]
add("enc-secret-ue-octal", ("# coding: unicode_escape\n#\\x0aAWS_ACCESS_KEY_ID = \"" + _oct + "\"\\x0aprint(\"" + MARK + "\")\n").encode(),
    codec="unicode_escape", program=False, group="encoded-credential", note="the credential's first letters as octal escapes")

# UTF-16/32 with no BOM.
for codec, enc in (("utf-16", "utf-16-le"), ("utf-16-le", "utf-16-le"), ("utf-16-be", "utf-16-be"), ("utf-32", "utf-32-le"), ("utf-32-be", "utf-32-be")):
    add(f"{codec}-nobom", f"# coding: {codec}\n".encode() + PAYLOAD.encode(enc), codec=codec, group="utf-16-32",
        note=f"ASCII cookie line, the program in {enc} with no byte-order mark")

# EBCDIC and other pages whose ASCII range is not ASCII.
for codec in ("cp037", "cp500", "cp1140", "cp864"):
    add(f"ebcdic-{codec}" if codec != "cp864" else "page-cp864", f"# coding: {codec}\n".encode() + ("\n" + PAYLOAD).encode(codec),
        codec=codec, group="ebcdic", note=f"ASCII cookie line, then a blank line and the program in {codec}")

# Stateful CJK codecs: full-width identifiers behind escape sequences.
for codec in ("iso2022_jp", "iso2022_jp_1", "iso2022_jp_2", "iso2022_jp_2004", "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "hz"):
    try:
        body = fullwidth_payload().encode(codec)
    except UnicodeError:
        continue
    add(f"stateful-{codec}", f"# coding: {codec}\n".encode() + body, codec=codec, group="stateful-cjk",
        note=f"identifiers in full-width letters written in {codec}; NFKC makes them the same program")

# Multi-byte codecs whose trail byte can be 0x5C.
for codec in ("shift_jis", "shift_jis_2004", "cp932", "big5", "big5hkscs", "cp950", "gbk", "gb18030", "johab"):
    p = trail5c_payload(codec)
    if p is None:
        continue
    add(f"trail5c-{codec}", f"# coding: {codec}\n".encode() + p.encode(codec), codec=codec, group="trail-0x5c",
        note=f"a {codec} character whose second byte is 0x5C closes a string: a raw-bytes reader sees the sink swallowed")
add("multibyte-cp949", "# coding: cp949\n# \ud55c\uad6d\uc5b4\n".encode("cp949") + PAYLOAD.encode("cp949"), codec="cp949",
    group="trail-0x5c", note="cp949 has no 0x5C trail byte: a plain foreign vector")

# Pages that decode a high byte to an ASCII quote (mac-arabic, mac-farsi).
for codec in ("mac-arabic", "mac-farsi"):
    qb = quote_byte(codec)
    if qb is None:
        continue
    q_raw, q = qb
    sink_line = (b"    label = " + q.encode() + b"a" + q_raw + b"; subprocess.call(cmd, shell=True); tail = " + q_raw + b"z" + q.encode() + b"\n")
    body = PAYLOAD.encode("ascii").replace(b"    subprocess.call(cmd, shell=True)\n", sink_line)  # ASCII decodes as itself here
    assert f"label = {q}a{q}; subprocess.call(cmd, shell=True); tail = {q}z{q}".encode() in body.decode(codec).encode()
    add(f"quote-{codec}", f"# coding: {codec}\n".encode() + body, codec=codec, group="quote-bytes",
        note=f"{codec} decodes byte 0x{q_raw.hex()} to {q!r}: CPython closes the string before the sink, a raw reader does not")

# idna, unknown and non-text codecs.
add("idna", ("# coding: idna\n" + PAYLOAD).encode(), codec="idna", group="other-codecs", note="idna is a text encoding CPython accepts")
add("unknown-codec", ("# coding: fendix-no-such-codec\n" + PAYLOAD).encode(), codec="fendix-no-such-codec", group="unknown",
    note="a name no codec answers to in a fresh interpreter")
add("nontext-rot13", ("# coding: rot13\n" + codecs.encode(PAYLOAD, "rot13")).encode(), codec="rot13", group="unknown",
    note="rot13 is a codec but not a text encoding")

# Run-time registration (R6-E6) and run-time takeover of a built-in name (D2-A).
CUSTOM_REG = (
    "import codecs\n"
    "\n"
    "# A codec name of the project's own: an alias of utf-7, registered at import.\n"
    "codecs.register(lambda name: codecs.lookup('utf-7') if name == 'fendix7' else None)\n"
)
add("custom-codec", codec="fendix7", group="must-pass",
    files={"codecreg.py": CUSTOM_REG.encode(), "app.py": ("# coding: fendix7\n" + HIDDEN7 + "\n").encode(), "main.py": b"import codecreg\nimport app\n"},
    note="R6-E6: codecreg.py registers 'fendix7' (utf-7) at run time; main.py imports it, then app.py runs the hidden program")


def takeover_reg(name: str, mark_only: bool = False) -> str:
    """A module that makes `name` mean utf-7 (or a codec that prints the
    takeover marker) before anything else looks it up."""
    target = (
        "codecs.CodecInfo(name='x', encode=lambda s, e='strict': (s.encode('latin-1'), len(s)),\n"
        "    decode=lambda b, e='strict': (\"print('" + TAKEOVER_MARK + "')\\n\", len(b)),\n"
        "    incrementaldecoder=type('D', (codecs.IncrementalDecoder,), {'decode': lambda self, b, final=False: \"print('" + TAKEOVER_MARK + "')\\n\" if b else ''}))"
        if mark_only else "codecs.lookup('utf-7')"
    )
    return (
        "import codecs, encodings\n"
        f"_NAME = {name!r}\n"
        f"_INFO = {target}\n"
        "def _keys(n):\n"
        "    l = n.lower()\n"
        "    ks = {n, l, l.replace('-', '_'), l.replace('_', '-'), l.replace(' ', '_'), encodings.normalize_encoding(l)}\n"
        "    return ks | {k.replace('.', '_') for k in ks}\n"
        "for _k in _keys(_NAME):\n"
        "    encodings._cache[_k] = _INFO\n"
        "codecs.register(lambda n: _INFO if n in _keys(_NAME) else None)\n"
    )


ALL_NAMES = sorted(set(encodings.aliases.aliases) | set(encodings.aliases.aliases.values()) | {m.name for m in pkgutil.iter_modules(encodings.__path__)})


def _canon(name):
    """The codec CPython's tokenizer resolves a cookie name to: its
    get_normal_name step first (Parser/tokenizer/helpers.c: the first 12
    characters, '_' as '-', lower case; utf-8 and utf-8-* are utf-8; latin-1,
    iso-8859-1, iso-latin-1 and their -* forms are iso-8859-1), then
    codecs.lookup. Only names the codec; every verdict is measured."""
    buf = "".join("-" if c == "_" else c.lower() for c in name[:12])
    if buf == "utf-8" or buf.startswith("utf-8-"):
        name = "utf-8"
    elif buf in ("latin-1", "iso-8859-1", "iso-latin-1") or buf.startswith(("latin-1-", "iso-8859-1-", "iso-latin-1-")):
        name = "iso-8859-1"
    try:
        return codecs.lookup(name).name
    except Exception:
        return None


_FAMILY = {"utf-8", "utf-8-sig", "iso8859-1", "ascii"}
TAKEOVER_SPELLINGS = sorted({n for n in ALL_NAMES if _canon(n) in _FAMILY} | {
    "UTF-8", "Utf8", "utf-8-x", "utf_8_x", "latin-1-x", "LATIN-1", "iso-latin-1", "iso_8859_1_1987", "US-ASCII", "us_ascii",
    "ISO-8859-1", "iso-8859-1",
})
for name in TAKEOVER_SPELLINGS + ["cp1252", "euc_jp", "koi8-r"]:
    add(f"takeover-{name}", codec=name, group="takeover", takeover=name,
        files={"codecreg.py": takeover_reg(name).encode(), "app.py": (f"# coding: {name}\n" + HIDDEN7 + "\n").encode(),
               "main.py": b"import codecreg\nimport app\n"},
        note=f"codecreg.py makes {name!r} mean utf-7 before app.py is imported; CPython runs the hidden program unless the spelling is takeover-immune")

# Takeover variants (OR-59): the registration hidden from a text search, and a
# target codec other than utf-7, so no heuristic on `_cache` or `+AAo-` works.
assert "#;" not in PAYLOAD
_CUSTOM_INFO = (
    "codecs.CodecInfo(name='x', encode=lambda s, e='strict': (s.encode('latin-1'), len(s)),\n"
    "    decode=lambda b, e='strict': (bytes(b).decode('latin-1').replace('#;', '\\n'), len(b)),\n"
    "    incrementaldecoder=type('D', (codecs.IncrementalDecoder,), {'decode': lambda self, b, final=False: bytes(b).decode('latin-1').replace('#;', '\\n')}))"
)
TAKEOVER_TARGETS = {
    "utf7": ("codecs.lookup('utf-7')", HIDDEN7),
    "unicode-escape": ("codecs.lookup('unicode_escape')", ue_hidden("\n" + PAYLOAD)),
    "raw-unicode-escape": ("codecs.lookup('raw_unicode_escape')", rue_hidden("\n" + PAYLOAD)),
    "custom": (_CUSTOM_INFO, "#" + ("\n" + PAYLOAD).replace("\n", "#;")),
}


def takeover_variant(name: str, mech: str, info_src: str) -> str:
    keys = (
        f"_l = {name!r}.lower()\n"
        f"_K = {{{name!r}, _l, _l.replace('-', '_'), _l.replace('_', '-'), _l.replace(' ', '_'),\n"
        "      getattr(__import__('enc' + 'odings'), 'normalize_encoding')(_l)}\n"
        "_K |= {k.replace('.', '_') for k in _K}\n"
    )
    if mech == "getattr":
        # No `encodings._cache` in the text.
        return ("import codecs\n" + keys + f"_INFO = {info_src}\n"
                "_c = getattr(__import__('enc' + 'odings'), '_ca' + 'che')\n"
                "for _k in _K:\n    _c[_k] = _INFO\n")
    # No `_cache` at all: put a search function ahead of the encodings package's
    # (codecs.unregister also clears the lookup cache).
    return ("import codecs, encodings\n" + keys + f"_INFO = {info_src}\n"
            "codecs.unregister(encodings.search_function)\n"
            "codecs.register(lambda n: _INFO if n in _K else None)\n"
            "codecs.register(encodings.search_function)\n")


for name in ("cp1252", "u8", "latin", "utf8", "latin1"):
    for mech in ("getattr", "reregister"):
        for tgt, (info_src, hidden) in TAKEOVER_TARGETS.items():
            add(f"takeover-{mech}-{tgt}-{name}", codec=name, group="takeover-variants", takeover=name,
                files={"codecreg.py": takeover_variant(name, mech, info_src).encode(),
                       "app.py": (f"# coding: {name}\n" + hidden + "\n").encode(),
                       "main.py": b"import codecreg\nimport app\n"},
                note=f"codecreg.py rebinds {name!r} to {tgt} via {mech}; CPython runs the hidden program unless the spelling is takeover-immune")

# BOM.
BOM = b"\xef\xbb\xbf"
add("bom-utf7", BOM + ("# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="bom",
    note="UTF-8 BOM and a conflicting utf-7 cookie: import and script refuse; -x skips line 1, BOM and cookie with it")
add("bom-utf7-line2", BOM + ("\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), codec="utf-7", group="bom",
    note="UTF-8 BOM, blank line 1, cookie on line 2: -x skips the BOM and honours the cookie")
add("bom-latin1", BOM + ("# coding: latin-1\n# caf\u00e9\n" + PAYLOAD).encode("latin-1"), codec="latin-1", group="bom",
    note="UTF-8 BOM and a latin-1 cookie; a latin-1-only byte follows, so a run proves the cookie applied (python -x skips the cookie line)")
add("bom-utf8", BOM + ("# coding: utf-8\n" + PAYLOAD).encode(), codec="utf-8", group="bom", note="UTF-8 BOM and an agreeing utf-8 cookie")
add("bom-only", BOM + PAYLOAD.encode(), group="bom", note="UTF-8 BOM, no cookie")

# Plain and ASCII-transparent controls.
add("plain-utf8", PAYLOAD.encode(), group="controls", note="no cookie")
add("plain-utf8-nonascii", ("# caf\u00e9\n" + PAYLOAD).encode(), group="controls", note="no cookie, a UTF-8 comment")
for codec, sample in (
    ("utf-8", "caf\u00e9"), ("utf8", "caf\u00e9"), ("UTF-8", "caf\u00e9"), ("utf-8-x", "caf\u00e9"), ("utf_8_sig", "caf\u00e9"),
    ("latin-1", "caf\u00e9"), ("iso-8859-15", "\u20ac"), ("cp1252", "\u20ac"), ("cp775", "\u0105"), ("koi8-r", "\u0436"),
    ("mac-roman", "\u00e9"), ("euc_jp", "\u65e5\u672c"), ("euc_kr", "\ud55c"), ("gb2312", "\u4e2d"), ("ascii", "plain"),
):
    enc = codecs.lookup(codec if codec != "utf-8-x" else "utf-8").name
    add(f"transparent-{codec}", (f"# -*- coding: {codec} -*-\n# {sample}\n" + PAYLOAD).encode(enc), codec=codec, group="transparent",
        note=f"an ASCII-transparent codec ({codec}) with a non-ASCII comment that only decodes under it")

# Extensions other than .py.
add("ext-pyi", ("# coding: utf-7\n" + HIDDEN7 + "\n").encode(), target="app.pyi", codec="utf-7", group="extensions",
    note=".pyi is Python source to Semgrep; the Python engine reads only .py", ext_expect={"python_engine": ["not_target"]})
add("ext-pyw", ("# coding: utf-7\n" + HIDDEN7 + "\n").encode(), target="app.pyw", codec="utf-7", group="extensions",
    note=".pyw: neither Semgrep nor the Python engine selects it", ext_expect={"semgrep": ["not_target"], "python_engine": ["not_target"]})
add("ext-shebang-noext", ("#!/usr/bin/env python3\n# coding: utf-7\n" + HIDDEN7 + "\n").encode(), target="run", codec="utf-7",
    group="extensions", note="an extension-less script whose line 1 is a Python shebang",
    ext_expect={"semgrep": ["not_target"], "python_engine": ["not_target"]})

# Not Python: a cookie means nothing; the file is read as written (E1-B6).
CLEAR_SECRET_LINE = f'AWS_ACCESS_KEY_ID = "{SECRET}"\n'
for rel, head in (("README.md", ""), ("config.yaml", ""), ("x.sh", "#!/bin/sh\n")):
    add(f"not-python-{rel}", (head + "# coding: utf-7\n" + CLEAR_SECRET_LINE).encode(), target=rel, codec="utf-7", kind="not_python",
        group="not-python", note=f"{rel} carries a utf-7 cookie; it is not Python, so every reader reads it as written")


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


def expand(v: dict) -> dict[str, bytes]:
    files = dict(v["files"])
    e = v.get("expand")
    if e:
        rest = files[v["target"]]
        t = e["terminator"].encode()
        n = e.get("line1_comment_bytes") or e["line1_fill_to_total"] - len(t) - len(rest)
        files[v["target"]] = b"#" + b"x" * (n - 1) + t + rest
    return files


def _norm_err(text: str, d: str) -> str:
    lines = text.strip().splitlines()
    last = lines[-1][:200] if lines else ""
    return last.replace(d, "<dir>")


def _run(argv, cwd, stdin=None):
    r = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=120, input=stdin)
    return r


PY = [sys.executable, "-E", "-s", "-B"]


def ground_truth(v: dict) -> dict:
    files = expand(v)
    with tempfile.TemporaryDirectory() as d:
        for rel, data in files.items():
            with open(os.path.join(d, rel), "wb") as fh:
                fh.write(data)
        with open(os.path.join(d, "flask.py"), "w") as fh:
            fh.write(FLASK_STUB)

        def result(r, introspected=None):
            ran = MARK.encode() in r.stdout or b"EXECUTED" in r.stdout
            if introspected is not None:
                ran = ran or introspected
            return {"exit": r.returncode, "payload_ran": ran, "error": _norm_err(r.stderr.decode("utf-8", "replace"), d) if r.returncode else ""}

        if "main.py" in files:
            return {"import": result(_run(PY + ["main.py"], d)), "script": None, "x": None}
        target = os.path.join(d, v["target"])
        code = (
            "import sys\n"
            f"sys.path.insert(0, {d!r})\n"
            f"data = open({target!r}, 'rb').read()\n"
            "g = {'__name__': 'm'}\n"
            f"exec(compile(data, {target!r}, 'exec'), g)\n"
            "print('GLOBALS', sorted(k for k in g if not k.startswith('__')))\n"
        )
        intro = v.get("introspect")
        imp = _run(PY + ["-c", code], d)
        imp_res = result(imp, (intro is not None and f"'{intro}'".encode() in imp.stdout))
        out = {"import": imp_res}
        for key, flags in (("script", []), ("x", ["-x"])):
            r = _run(PY + flags + [target], d)
            seen = None
            if intro is not None:
                probe = _run(PY + flags + ["-i", target], d, stdin=b"print('GLOBALS', sorted(k for k in globals() if not k.startswith('__')))\n")
                seen = f"'{intro}'".encode() in probe.stdout
            out[key] = result(r, seen)
        return out


def takeover_ran(name: str) -> bool:
    """Whether a module can make `name` mean another codec for a later
    `# coding: name` module (CPython 3.14.5, measured)."""
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "reg.py"), "w") as fh:
            fh.write(takeover_reg(name, mark_only=True))
        with open(os.path.join(d, "victim.py"), "wb") as fh:
            fh.write(f"# coding: {name}\n".encode() + b"x = 1\n")
        with open(os.path.join(d, "main.py"), "w") as fh:
            fh.write("import reg\nimport victim\n")
        r = _run(PY + ["main.py"], d)
        return TAKEOVER_MARK.encode() in r.stdout


def transparent_codecs() -> list[str]:
    names = set(encodings.aliases.aliases.values()) | {m.name for m in pkgutil.iter_modules(encodings.__path__)}
    ascii_bytes = bytes(range(128))
    out = set()
    for n in sorted(names):
        try:
            info = codecs.lookup(n)
        except (LookupError, ImportError, AttributeError):
            continue
        if not getattr(info, "_is_text_encoding", True):
            continue
        try:
            if ascii_bytes.decode(info.name) != ascii_bytes.decode("ascii"):
                continue
            if any(bytes([b]).decode(info.name) != chr(b) for b in range(128)):
                continue
        except Exception:
            continue
        ok = True
        for probe in (b"+AAo-", b"\\u000a", b"\\x0a", b"~{", b"\x1b$B", b"xn--80ak6aa92e.com"):
            try:
                ok = ok and probe.decode(info.name) == probe.decode("ascii")
            except Exception:
                ok = False
        single = {}
        for a in range(128, 256):
            if not ok:
                break
            try:
                s = bytes([a]).decode(info.name)
                single[a] = s
                ok = not any(ord(c) < 128 for c in s)
            except UnicodeDecodeError:
                pass
        for a in range(128, 256):
            if not ok:
                break
            for b in range(256):
                try:
                    s = bytes([a, b]).decode(info.name)
                except UnicodeDecodeError:
                    continue
                if (b < 128 and s != single.get(a, "\0invalid") + chr(b)) or (b >= 128 and any(ord(c) < 128 for c in s)):
                    ok = False
                    break
        if ok:
            out.add(info.name)
    return sorted(out)


TRANSPARENT = set(transparent_codecs())

POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8)

# The name table: every codec name CPython knows (alias keys, alias values and
# every module of the encodings package).
NAME_BODY = b"x = 1\n"


def name_truth(name: str) -> dict:
    data = f"# coding: {name}\n".encode() + NAME_BODY
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "n.py")
        with open(p, "wb") as fh:
            fh.write(data)
        code = f"data = open({p!r}, 'rb').read()\nexec(compile(data, {p!r}, 'exec'), {{}})\n"
        imp = _run(PY + ["-c", code], d)
        scr = _run(PY + [p], d)
        return {
            "import": {"exit": imp.returncode, "error": _norm_err(imp.stderr.decode("utf-8", "replace"), d) if imp.returncode else ""},
            "script": {"exit": scr.returncode, "error": _norm_err(scr.stderr.decode("utf-8", "replace"), d) if scr.returncode else ""},
        }


REFUSAL = ("unknown encoding", "is not a text encoding", "encoding problem")


def _usable(name: str) -> bool:
    """Whether the codec CPython resolves `name` to is a text encoding that can
    carry a program at all: it round-trips ASCII source. The `undefined` codec
    and the bytes-to-bytes codecs cannot; a codec whose ASCII range differs
    (EBCDIC) can, in its own bytes."""
    c = _canon(name)
    if c is None or not getattr(codecs.lookup(c), "_is_text_encoding", True):
        return False
    try:
        return codecs.decode(codecs.encode("x = 1\n", c), c) == "x = 1\n"
    except Exception:
        return False


def name_verdict(truth: dict, name: str) -> tuple[str, str | None]:
    errs = [truth["import"]["error"], truth["script"]["error"]]
    if any("unknown encoding" in e for e in errs):
        return "unknown", None
    failed_everywhere = truth["import"]["exit"] != 0 and truth["script"]["exit"] != 0
    if failed_everywhere and (all(any(r in e for r in REFUSAL) for e in errs) or not _usable(name)):
        # CPython refuses the name on every path, or its codec cannot carry a
        # program at all (the `undefined` codec, a bytes-to-bytes codec).
        return "refused", None
    c = _canon(name)
    return ("transparent" if c in TRANSPARENT else "foreign"), c


# Measured case and separator variants of every name (U8, UTF, L1, Latin1, ASCII, ...).
_seen = set(ALL_NAMES)
VARIANTS = []
for _n in ALL_NAMES:
    for _v in (_n.upper(), _n.capitalize(), _n.replace("_", "-"), _n.replace("-", "_")):
        if _v not in _seen:
            _seen.add(_v)
            VARIANTS.append((_v, _n))
TABLE = [(n, None) for n in ALL_NAMES] + VARIANTS
name_truths = list(POOL.map(name_truth, [n for n, _ in TABLE]))
name_rows = []
transparent_spellings = []
for (name, base), truth in zip(TABLE, name_truths):
    verdict, canon = name_verdict(truth, name)
    if verdict == "transparent":
        transparent_spellings.append(name)
    name_rows.append({"name": name, "variant_of": base, "verdict": verdict, "codec": canon, "cpython": truth})
immune_by_name = dict(zip(transparent_spellings, (not ran for ran in POOL.map(takeover_ran, transparent_spellings))))

EXP = {
    "transparent": {"semgrep": ["evaluated"], "secrets": ["evaluated"], "python_engine": ["decoded"]},
    "foreign": {"semgrep": ["lost"], "secrets": ["lost"], "python_engine": ["decoded", "lost"]},
    "unknown": {"semgrep": ["lost"], "secrets": ["lost"], "python_engine": ["lost"]},
    "refused": {"semgrep": ["evaluated", "lost"], "secrets": ["evaluated", "lost"], "python_engine": ["decoded", "lost"]},
}
D2A_LOST = {"semgrep": ["lost"], "secrets": ["lost"]}
for i, row in enumerate(name_rows):
    row["file"] = "n%03d.py" % i
    row["takeover_immune"] = immune_by_name.get(row["name"])
    row["expect"] = EXP[row["verdict"]]
    if row["verdict"] == "transparent" and not row["takeover_immune"]:
        row["expect_under_d2a"] = {**EXP["transparent"], **D2A_LOST}
        row["predicate_verdicts_under_d2a"] = ["foreign"]
    row["predicate_verdicts"] = [row["verdict"]] if row["verdict"] != "refused" else ["refused", "foreign", "unknown"]

# Immunity of every vector's own cookie spelling.
cookie_spellings = sorted({v["codec"] for v in V if v["codec"]})
immune_spelling = dict(zip(cookie_spellings, (not ran for ran in POOL.map(takeover_ran, cookie_spellings))))

ANY = ["evaluated", "lost"]
problems = []
out_vectors = []
truths = list(POOL.map(lambda v: None if v["kind"] == "not_python" else ground_truth(v), V))
for v, gt in zip(V, truths):
    files = expand(v)
    size = len(files[v["target"]])
    canon = _canon(v["codec"]) if v["codec"] else None
    if v["kind"] == "not_python":
        verdict = "not_python"
        exp = {"semgrep": ["not_target"], "secrets": ["evaluated"], "python_engine": ["not_target"]}
        takeover_d2a = None
    else:
        paths = [p for p in (gt["import"], gt["script"], gt["x"]) if p is not None]
        errs = [p["error"] for p in paths]
        ran_import = gt["import"]["payload_ran"]
        ran_other = any(p["payload_ran"] for p in (gt["script"], gt["x"]) if p is not None)
        printed = ran_import or ran_other
        any_ok = any(p["exit"] == 0 for p in paths)
        # Precedence: a name only a run-time registration can supply is lost
        # whatever another path did with it.
        if any("unknown encoding" in e for e in errs) or (v["id"] == "custom-codec"):
            verdict = "unknown"
        elif printed and canon is not None:
            verdict = "transparent" if canon in TRANSPARENT else "foreign"
        elif not any_ok:
            verdict = "refused"
        else:
            verdict = "plain"
        if verdict in ("plain", "transparent"):
            exp = {"semgrep": ["evaluated"], "secrets": ["evaluated"],
                   "python_engine": ["finding"] if (v["program"] and ran_import) else ["decoded", "finding"]}
        elif verdict == "foreign":
            if v["finding"] or (v["program"] and ran_import):
                py = ["finding"]
            elif v["program"] and ran_other:
                py = ["finding", "lost"]
            else:
                py = ["decoded", "finding"]
            if not ran_import and ran_other and not v["program"]:
                py = ["decoded", "finding", "lost"]
            exp = {"semgrep": ["lost"], "secrets": ["lost"], "python_engine": py}
        elif verdict == "unknown":
            exp = {"semgrep": ["lost"], "secrets": ["lost"], "python_engine": ["lost"]}
        else:
            exp = {"semgrep": list(ANY), "secrets": list(ANY), "python_engine": ["finding", "decoded", "lost"]}
        if size > CAP:
            exp["semgrep"] = ["lost"]
            exp["python_engine"] = ["lost"]
        takeover_d2a = None
        if v["takeover"]:
            hijacked = gt["import"]["payload_ran"]
            if hijacked:
                # OR-59: under D2 as written the name is UTF-8-equivalent, so
                # every reader evaluates a file whose program it cannot see: a
                # false clean D2 documents. Only D2-A makes it lost.
                exp = {"semgrep": ["evaluated"], "secrets": ["evaluated"], "python_engine": ["decoded"]}
                takeover_d2a = {"semgrep": ["lost"], "secrets": ["lost"], "python_engine": ["decoded", "lost"]}
            else:
                exp = {"semgrep": ["evaluated"], "secrets": ["evaluated"], "python_engine": ["decoded", "finding"]}
        for k, val in (v["ext_expect"] or {}).items():
            exp[k] = val
        # Consistency with the construction.
        if v["id"] in ("c7-cr-secret", "c7-long1-secret", "c8-ue-cr-secret", "c7-cr") and verdict != "foreign":
            problems.append(f"{v['id']}: must-pass fixture measured {verdict}: {gt}")
        # A cookie is never credited with a run that only `python -x` made, after
        # skipping the line holding the cookie: the program ran as plain text, so
        # the cookie was never applied (the first bom-latin1 measured "transparent"
        # that way: BOM + latin-1 cookie is refused on import and as a script, and
        # -x ran the ASCII payload without ever reading the cookie).
        ran_script = gt["script"] is not None and gt["script"]["payload_ran"]
        ran_x_only = gt["x"] is not None and gt["x"]["payload_ran"] and not ran_import and not ran_script
        if verdict in ("transparent", "foreign") and v["codec"] and ran_x_only:
            first_line = files[v["target"]].split(b"\n", 1)[0].lower()
            if v["codec"].lower().encode() in first_line:
                problems.append(f"{v['id']}: measured {verdict} from a python -x run that skipped the line holding the "
                                f"cookie ({v['codec']!r}): the cookie was never applied; {gt}")
        if v["group"] == "transparent" and verdict != "transparent":
            problems.append(f"{v['id']}: built transparent, measured {verdict}: {gt}")
    e = {"id": v["id"], "group": v["group"], "note": v["note"], "target": v["target"],
         "files": {rel: base64.b64encode(data).decode() for rel, data in v["files"].items()}}
    if v.get("expand"):
        e["expand"] = v["expand"]
    e["target_bytes"] = size
    e["cookie_codec"] = v["codec"]
    e["cpython"] = None if gt is None else {"codec": canon if verdict in ("foreign", "transparent") else None, **gt}
    e["verdict"] = verdict
    e["takeover"] = bool(v["takeover"])
    if v["codec"] is not None:
        e["cookie_takeover_immune"] = immune_spelling.get(v["codec"])
    printed_any = bool(gt) and any(p["payload_ran"] for p in (gt["import"], gt["script"], gt["x"]) if p)
    # The program CPython runs holds the credential.
    e["secret"] = SECRET if verdict == "not_python" or (printed_any and (v["program"] or "secret" in v["id"])) else None
    e["secret_in_bytes"] = SECRET.encode() in files[v["target"]]
    e["python_engine_finding"] = (v["finding"] or (SHELL_ID if v["program"] else None)) if "finding" in exp["python_engine"] else None
    e["controls"] = ["ok.py"] if "ok.py" in v["files"] and v["target"] != "ok.py" else []
    e["expect"] = exp
    if verdict == "transparent" and v["codec"] is not None and not immune_spelling.get(v["codec"]) and not v["takeover"]:
        e["expect_under_d2a"] = {**exp, **D2A_LOST}
    if verdict != "not_python" and takeover_d2a is not None:
        e["d2_documented_false_clean"] = True
        e["expect_under_d2a"] = takeover_d2a
    if v["takeover"] or verdict == "not_python":
        e["predicate_verdicts"] = None
    elif verdict == "refused" or (gt and gt["import"]["exit"] and gt["script"]["exit"] and verdict == "plain"):
        e["predicate_verdicts"] = sorted({verdict, "refused"} | ({"foreign", "unknown"} if verdict == "refused" else set()))
    else:
        e["predicate_verdicts"] = [verdict]
    if "expect_under_d2a" in e:
        e["predicate_verdicts_under_d2a"] = ["foreign"]
    out_vectors.append(e)

if problems:
    sys.stderr.write("ground truth disagrees with the construction:\n  " + "\n  ".join(problems) + "\n")
    sys.exit(1)

if platform.python_version() != REFERENCE:
    sys.stderr.write(f"warning: the reference interpreter is CPython {REFERENCE}, this is {platform.python_version()}\n")

INTERP = {"version": platform.python_version(), "implementation": platform.python_implementation(),
          "build": " ".join(platform.python_build()), "source": "the engine image's /usr/local/bin/python3 (review/fendix-engine:3.7.0)"}
POLICY = (
    "Owner decision D2 (default 'expect'): plain/transparent -> every reader evaluates; foreign -> the Python engine decodes, "
    "Semgrep and secrets record lost evaluation; unknown -> lost everywhere; refused -> any outcome. 'expect_under_d2a' is "
    "the corrected D2-A (OWNER-DECISIONS §0.8): only takeover-immune spellings stay UTF-8-equivalent. A taken-over, "
    "non-immune name (takeover-* vectors) is D2's documented false clean ('d2_documented_false_clean'), asserted lost "
    "only under D2-A (OR-59). No outcome may crash the Python engine (OR-53). Paths measured: import (compile(bytes)+exec), script, "
    "and python -x (OR-49)."
)

doc = {
    "schema": 2,
    "about": "PEP 263 source-encoding vectors shared by the Go and Python tests (Round 6, WS-E1). Generated by "
             "gen_pep263_vectors.py on the reference interpreter; never edited by hand.",
    "policy": POLICY,
    "reference_interpreter": INTERP,
    "outcomes": {
        "evaluated": "the reader does not record the file as lost evaluation",
        "lost": "the reader records the file as lost evaluation (Semgrep: not parsed; secrets: unreadable; Python engine: AnalysisIncomplete names it)",
        "not_target": "the reader does not select the file; it must not record it as lost",
        "finding": "the Python engine reports python_engine_finding at the target",
        "decoded": "the Python engine analyses the file and does not record it as lost",
        "crashed": "an exception escaped the Python engine: never an allowed outcome, since it costs every other file (OR-53)",
    },
    "payload_marker": MARK,
    "transparent_codecs": sorted(TRANSPARENT),
    "takeover_immune_spellings": sorted(n for n, im in immune_by_name.items() if im),
    "vectors": out_vectors,
}
names_doc = {
    "schema": 1,
    "about": "Every codec name CPython 3.14.5 knows (encodings.aliases keys and values and every encodings module): "
             "what CPython does with `# coding: <name>` followed by `x = 1`, the codec it resolves to, whether another "
             "module can take the name over at run time, and the outcome each reader must report. Generated by "
             "gen_pep263_vectors.py; never edited by hand.",
    "policy": POLICY,
    "reference_interpreter": INTERP,
    "body": NAME_BODY.decode(),
    "normalisation": (
        "A cookie name reaches a codec the way CPython 3.14.5 sends it: the tokenizer's get_normal_name looks at the "
        "first 12 characters with '_' read as '-' and letters lower-cased; 'utf-8' and 'utf-8-*' become utf-8, "
        "'latin-1', 'iso-8859-1', 'iso-latin-1' and their '-*' forms become iso-8859-1, and those names are decoded on "
        "a C fast path that no run-time registration reaches. Every other name, unchanged, goes to codecs.lookup, which "
        "lower-cases it and lets encodings.search_function collapse each run of characters other than letters, digits "
        "and '.' into '_' before reading encodings.aliases. Rows with 'variant_of' are case and separator variants of a "
        "base name; every verdict and takeover_immune value here is measured, not derived from this description."
    ),
    "control": {"file": "ok.py", "b64": base64.b64encode(PAYLOAD.encode()).decode(), "finding": SHELL_ID,
                "rule": "every tree a name is tested in also holds this plain file, and its finding must be reported (OR-53)"},
    "names": name_rows,
}
# ---------------------------------------------------------------------------
# The production codec table the predicate reads (Go embeds it, Python carries
# a copy in scope_evidence.py). It is CPython's own data: the alias table, and
# for every codec module the codec it registers and its measured class, plus
# the normal forms CPython decodes on a C fast path. The model below reproduces
# every measured row of the name table from it, or generation fails.
# ---------------------------------------------------------------------------
import importlib


def _module_class(entry) -> str:
    if entry.name in TRANSPARENT:
        return "transparent"
    if not getattr(entry, "_is_text_encoding", True):
        return "refused"
    try:
        if entry.decode(entry.encode("x = 1\n")[0])[0] != "x = 1\n":
            return "refused"
    except Exception:
        return "refused"
    return "foreign"


MODULES = {}
for _m in sorted(set(encodings.aliases.aliases.values()) | {m.name for m in pkgutil.iter_modules(encodings.__path__)}):
    try:
        _entry = importlib.import_module("encodings." + _m).getregentry()
    except Exception:
        continue
    if not isinstance(_entry, codecs.CodecInfo):
        _entry = codecs.CodecInfo(*_entry)
    MODULES[_m] = {"codec": _entry.name, "class": _module_class(_entry)}


def m_normal_name(s: str) -> str:
    """Parser/tokenizer/helpers.c get_normal_name."""
    buf = "".join("-" if c == "_" else c.lower() for c in s[:12])
    if buf == "utf-8" or buf.startswith("utf-8-"):
        return "utf-8"
    if buf in ("latin-1", "iso-8859-1", "iso-latin-1") or buf.startswith(("latin-1-", "iso-8859-1-", "iso-latin-1-")):
        return "iso-8859-1"
    return s


def m_normalize(s: str) -> str:
    """encodings.normalize_encoding on a lower-cased ASCII name (also what C's
    _Py_normalize_encoding makes of it): each run of characters other than
    letters, digits and '.' becomes one '_' between kept characters."""
    out, punct = [], False
    for c in s.lower():
        if (c.isascii() and c.isalnum()) or c == ".":
            if punct and out:
                out.append("_")
            out.append(c)
            punct = False
        else:
            punct = True
    return "".join(out)


FAST = sorted({m_normalize(n) for n, im in immune_by_name.items() if im and m_normal_name(n) not in ("utf-8", "iso-8859-1")})
ALIASES = dict(sorted(encodings.aliases.aliases.items()))


def m_resolve(name: str):
    """(verdict, codec, immune) of `# coding: name` from the table alone."""
    n = m_normal_name(name)
    if n == "utf-8":
        return "transparent", "utf-8", True
    if n == "iso-8859-1":
        return "transparent", "iso8859-1", True
    norm = m_normalize(name)
    aliased = ALIASES.get(norm) or ALIASES.get(norm.replace(".", "_"))
    for mod in ([aliased] if aliased else []) + [norm]:
        if mod and "." not in mod and mod in MODULES:
            e = MODULES[mod]
            cls = e["class"]
            return cls, (e["codec"] if cls in ("transparent", "foreign") else None), (m_normalize(name) in FAST) if cls == "transparent" else None
    return "unknown", None, None


for row in name_rows:
    mv, mc, mi = m_resolve(row["name"])
    if (mv, mc) != (row["verdict"], row["codec"]) or (mv == "transparent" and mi != row["takeover_immune"]):
        problems.append(f"model disagrees with CPython on # coding: {row['name']}: model {(mv, mc, mi)}, measured "
                        f"{(row['verdict'], row['codec'], row['takeover_immune'])}")
if problems:
    sys.stderr.write("ground truth disagrees with the model:\n  " + "\n  ".join(problems[:40]) + "\n")
    sys.exit(1)

TABLE = {
    "schema": 1,
    "about": "PEP 263 codec table for scope.ClassifyPythonSource (Go, embedded) and "
             "scope_evidence.python_source_encoding (Python, copied). Generated by gen_pep263_vectors.py from CPython "
             f"{platform.python_version()}; never edited by hand.",
    "aliases": ALIASES,
    "modules": MODULES,
    "fast_path_normal_forms": FAST,
}
TABLE_TEXT = json.dumps(TABLE, indent=1, ensure_ascii=True, sort_keys=True) + "\n"
TABLE_COMPACT = json.dumps(TABLE, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
with open(os.path.join(OUT, "pep263_codec_table.json"), "w", encoding="utf-8", newline="\n") as fh:
    fh.write(TABLE_TEXT)
if os.path.abspath(OUT) != HERE:
    committed = os.path.join(HERE, "pep263_codec_table.json")
    if os.path.exists(committed) and open(committed, encoding="utf-8").read() != TABLE_TEXT:
        sys.stderr.write("the committed pep263_codec_table.json is stale: regenerate into testdata/\n")
        sys.exit(1)
# The guard that the Python module carries this table needs that module. When the
# generator sits in the repository layout (.../go/internal/scope/testdata) its
# absence is an error, never a silent skip; with only testdata mounted (the
# reference-interpreter command in the docstring) the layout is not there, and
# the guard cannot run.
REPO_LAYOUT = os.path.normpath(HERE).split(os.sep)[-4:] == ["go", "internal", "scope", "testdata"]
if REPO_LAYOUT and not os.path.exists(PY_EVIDENCE):
    sys.stderr.write(f"{PY_EVIDENCE} is absent, so the PEP 263 codec table it must carry cannot be checked: "
                     "the generator is in the repository layout and refuses to skip the guard\n")
    sys.exit(1)
if os.path.exists(PY_EVIDENCE):
    src = open(PY_EVIDENCE, encoding="utf-8").read()
    block = (TABLE_BEGIN + " (gen_pep263_vectors.py --sync-python; do not edit)\n"
             "_PEP263_CODEC_TABLE_JSON = r" + "'" * 3 + TABLE_COMPACT + "'" * 3 + "\n" + TABLE_END)
    a, b = src.find(TABLE_BEGIN), src.find(TABLE_END)
    current = src[a:b + len(TABLE_END)] if a >= 0 and b > a else None
    if current != block:
        if SYNC_PYTHON and current is not None:
            with open(PY_EVIDENCE, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(src[:a] + block + src[b + len(TABLE_END):])
        else:
            sys.stderr.write("python/analyzers/scope_evidence.py carries a stale or missing PEP 263 codec table: "
                             "run gen_pep263_vectors.py --sync-python\n")
            sys.exit(1)

with open(os.path.join(OUT, "pep263_vectors.json"), "w", encoding="utf-8", newline="\n") as fh:
    fh.write(json.dumps(doc, indent=1, ensure_ascii=True) + "\n")
with open(os.path.join(OUT, "pep263_codec_names.json"), "w", encoding="utf-8", newline="\n") as fh:
    fh.write(json.dumps(names_doc, indent=1, ensure_ascii=True) + "\n")
print(f"{len(out_vectors)} vectors, {len(ALL_NAMES)} codec names + {len(VARIANTS)} variants")
