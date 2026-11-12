"""What the Python engine may leave unread, and the evidence that says so (D6').

Decision D6'. Never exclude first-party source because of its file name or
directory alone. The engine used to skip `node_modules`, `vendor`, `dist`,
`build`, `.venv`, `venv`, `.tox` and `__pycache__` by directory name, and
`*.min.js` and every JavaScript line over 500 characters by shape, so a
repository that kept its own code in `vendor/` or `build/`, or wrote a long
line, read as scanned. A name is a claim, not evidence. A path is out of scope
only when something deterministic and auditable in the repository says it is
not the project's own code:

* a virtual environment: the directory holds `pyvenv.cfg`, the file the
  interpreter writes when it creates one;
* installed Python packages: a `*.dist-info/RECORD` lists, file by file, what
  an installer put there; the top-level entries it names are installed code;
* installed npm packages: a child of a `node_modules` directory whose
  `package.json` names a package and its version;
* Git metadata: a `.git` directory that holds `HEAD`;
* a generated, minified or vendored file (JavaScript, or a Python or
  JavaScript file too large to read): a generator header in the first comment
  lines (`@generated`, "Code generated ... DO NOT EDIT.", the protocol buffer
  compiler's, "DO NOT EDIT" beside "generated"), a known library identified by
  its own banner, its own identifier in the body and its size, or minification
  measured from the content. These are the rules of `go/internal/scope`; the
  two must agree (see the block comment above `HEAD_BYTES`).

Anything else is in scope. A directory that is merely called `vendor` or
`build` is walked and its files are analysed; so is a `.min.js` file whose
content is ordinary code. Every path left out is recorded with its reason
(`SourceWalk.declared`) and reported by name in the status detail (see
`status_detail`), so the scope of a scan is visible and nothing is dropped
silently.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

Entry = Tuple[str, str]  # (path, reason)

# The largest metadata file read to decide a directory is installed code.
_MAX_EVIDENCE_BYTES = 5_000_000

# --- file evidence: the same rules as go/internal/scope/classify.go ----------
#
# The Python engine and the Go analysers must agree on what is "not the
# project's own code" (redteam4-d6-04, DE4-09): one file cannot be declared out
# of scope by one analyser and a coverage gap in another, and a string literal
# that says "DO NOT EDIT" must not hide first-party code. These are the Go
# classifier's rules, read from the same evidence in the same order (minified,
# vendored library, generator header, compiled output). A change to one needs
# the same change in the other; `tests/test_rem_py4_scope.py` pins the shared
# cases.

# What is read of a file: its first HEAD_BYTES, and for compiled output its last
# TAIL_BYTES.
HEAD_BYTES = 64 * 1024
TAIL_BYTES = 2 * 1024

# Minified thresholds (go: minifiedLongLine and friends). A file is minified
# only when at least 90% of the bytes it holds lie in lines over
# MINIFIED_LONG_LINE bytes, those lines hold at least MINIFIED_MIN_LONG_BYTES,
# one byte in MINIFIED_SYNTAX_ONE_IN of them is one of ; { } ( ) =, and it has
# no more than MINIFIED_MAX_SHORT_LINES non-blank ordinary lines.
MINIFIED_LONG_LINE = 250
MINIFIED_MIN_LONG_BYTES = 1024
MINIFIED_MAX_SHORT_LINES = 40
MINIFIED_SYNTAX_ONE_IN = 20
# Kept for callers that name it: the line length minification is judged on.
LONG_LINE = MINIFIED_LONG_LINE

_RE = re.ASCII
# A leading comment that is the library's own banner, and the library's own
# identifier in the body (go: vendorLibraries).
_VENDOR_BODY_HITS = 3
_VENDOR_MIN_BYTES = 8 << 10
_VER = r"v?\d+\.\d+"


def _lib(name: str, subject: str, body: str) -> Tuple[str, "re.Pattern[str]", "re.Pattern[str]"]:
    return (
        name,
        re.compile(r"(?i)^(?:@(?:license|preserve) )?(?:" + subject + ")", _RE),
        re.compile(body, _RE),
    )


_VENDOR_LIBRARIES = [
    _lib("jquery", r"jQuery(?: JavaScript Library| UI(?: -)?| Mobile| Migrate| Validation Plugin)?,? " + _VER, r"(?i)jquery"),
    _lib("bootstrap", r"Bootstrap(?:\.js)? " + _VER, r"(?i)bootstrap|\.bs\."),
    _lib("underscore", r"Underscore\.js " + _VER, r"_wrapped|_chain|(?i:underscore)"),
    _lib("lodash", r"Lodash\b", r"(?i)lodash"),
    _lib("backbone", r"Backbone\.js " + _VER, r"Backbone"),
    _lib("moment", r"moment\.js\b", r"(?i)moment"),
    _lib("angular", r"Angular(?:JS)? " + _VER, r"(?i)angular"),
    _lib("react", r"React(?:-?DOM)? " + _VER, r"(?i)react"),
    _lib("vue", r"Vue\.js " + _VER, r"Vue"),
    _lib("d3", r"(?:https?://d3js\.org|D3\.js) " + _VER, r"\bd3\b|\bd3\."),
    _lib("chart.js", r"Chart\.js " + _VER, r"(?i)chart"),
    _lib("popper", r"(?:@popperjs/core|Popper\.js|Popper) " + _VER, r"(?i)popper"),
    _lib("highlight.js", r"highlight\.js " + _VER, r"hljs"),
    _lib("hammer", r"Hammer\.JS - " + _VER, r"Hammer"),
    _lib("zepto", r"Zepto " + _VER, r"Zepto"),
    _lib("modernizr", r"modernizr " + _VER, r"(?i)modernizr"),
    _lib("handlebars", r"handlebars " + _VER, r"Handlebars"),
    _lib("select2", r"Select2 " + _VER, r"(?i)select2"),
    _lib("datatables", r"DataTables " + _VER, r"DataTable"),
    _lib("leaflet", r"Leaflet " + _VER, r"Leaflet"),
    _lib("knockout", r"Knockout JavaScript library " + _VER, r"\bko\."),
    _lib("highcharts", r"Highcharts(?: JS| Stock| Maps| Gantt)? " + _VER, r"Highcharts"),
    _lib("socket.io", r"Socket\.IO " + _VER, r"(?i)socket"),
    _lib("three.js", r"Copyright 20\d\d(?:-20\d\d)? Three\.js Authors|@author (?:mrdoob|qiao)\b", r"THREE"),
    _lib("ace", r"(?:\*+ ?)?BEGIN LICENSE BLOCK\b.*Ajax\.org B\.V\.", r"\bace\b"),
    _lib("pdf.js", r"@licstart .*Copyright 20\d\d Mozilla Foundation", r"(?i)pdf"),
]

# What application code does and no table library does: read an HTTP request or
# start a web server.
_REQUEST_USE = re.compile(
    r"\b(?:req|request)\.(?:query|body|params|cookies)\b"
    r"|\b(?:require\(|from )['\"](?:express|koa|fastify|http|child_process)['\"]",
    _RE,
)

_COMMENT_OPEN = re.compile(r"^(?:/\*+!?|//!?|#!?)\s*", _RE)
_COMMENT_DECO = re.compile(r"^\s*(?:\*+|//+!?|#+)\s?", _RE | re.MULTILINE)
_COMMENT_CLOSE = re.compile(r"\*+/\s*$", _RE)
_SPACES = re.compile(r"\s+", _RE)

_GO_GENERATED = re.compile(r"^// Code generated .* DO NOT EDIT\.?\s*$", _RE | re.MULTILINE)
_AT_GENERATED = re.compile(r"(^|[\s/*#;])@generated([\s:/*]|$)", _RE)
_DO_NOT_EDIT = re.compile(r"(?i)\bdo not (?:edit|modify)\b", _RE)
_GENERATED = re.compile(
    r"(?i)\b(?:auto-?generated|automatically generated|generated (?:file|code|by)"
    r"|code generated|this file (?:is|was) generated)\b",
    _RE,
)
_GENERATED_BY = re.compile(
    r"(?i)\bgenerated by [A-Za-z0-9_.\-]+(?: [A-Za-z0-9_.\-]+)? v?\d+\.\d+", _RE
)
_PROTOBUF = re.compile(
    r"Generated by the protocol buffer compiler|protoc-gen-[a-z0-9-]+|source: [^\s]+\.proto",
    _RE,
)
_OTHER_GEN = re.compile(
    r"(?i)Autogenerated by Thrift Compiler|OpenAPI Generator|swagger-codegen"
    r"|auto generated by the swagger code generator|GENERATED CODE -- DO NOT EDIT",
    _RE,
)
# How far into a file a generator header is looked for.
_GENERATOR_HEADER_LINES = 25

_SOURCE_MAP_REF = re.compile(r"^\s*(?://|/\*)[#@]\s*sourceMappingURL=\S+", _RE | re.MULTILINE)
_WEBPACK_BOOT = re.compile(r"// webpackBootstrap")


def _head_text(text: str) -> str:
    """The first `HEAD_BYTES` bytes of `text` (as the Go side reads them)."""
    data = text.encode("utf-8", errors="replace")
    if len(data) <= HEAD_BYTES:
        return text
    return data[:HEAD_BYTES].decode("utf-8", errors="ignore")


def generated_marker(text: str) -> Optional[str]:
    """"generator header" when the first lines of `text` are a generator's
    header, else None. Only comment lines count, so a line of code or a string
    that says "DO NOT EDIT" is not evidence (redteam4-d6-04). Same rule as
    go/internal/scope `hasGeneratorHeader`."""
    body = text[1:] if text.startswith("\ufeff") else text
    comments: List[str] = []
    in_block = False
    for i, line in enumerate(body.split("\n", _GENERATOR_HEADER_LINES)):
        if i >= _GENERATOR_HEADER_LINES:
            break
        t = line.strip()
        if in_block:
            comments.append(t)
            if "*/" in t:
                in_block = False
        elif t.startswith("/*"):
            comments.append(t)
            in_block = "*/" not in t
        elif t.startswith(("//", "#", "--", ";", "<!--")):
            comments.append(t)
        elif t == "":
            continue
        else:
            # Code: a generator's header precedes it.
            break
    c = "\n".join(comments) + ("\n" if comments else "")
    if not c:
        return None
    if _GO_GENERATED.search(c) or _PROTOBUF.search(c) or _OTHER_GEN.search(c):
        return "generator header"
    if _AT_GENERATED.search(c):
        return "generator header"
    if _DO_NOT_EDIT.search(c) and _GENERATED.search(c):
        return "generator header"
    if _GENERATED_BY.search(c):
        return "generator header"
    return None


def _leading_comment(head: str) -> str:
    s = (head[1:] if head.startswith("\ufeff") else head).lstrip(" \t\r\n")[:4096]
    if s.startswith("/*"):
        k = s.find("*/")
        return s[: k + 2] if k >= 0 else s
    if s.startswith(("//", "#")):
        out = []
        for line in s.split("\n"):
            t = line.strip()
            if not t.startswith(("//", "#")):
                break
            out.append(t)
        return "\n".join(out) + "\n"
    return ""


def _banner_text(c: str) -> str:
    c = c.strip()
    c = _COMMENT_OPEN.sub("", c, count=1)
    c = _COMMENT_CLOSE.sub("", c, count=1)
    c = _COMMENT_DECO.sub("", c)
    return _SPACES.sub(" ", c).strip()


def library_banner(head: str, size: Optional[int] = None) -> Optional[str]:
    """The name of the known library `head` (the start of a file of `size`
    bytes) is, else None. All three must hold (go: `isVendoredBanner`): the file
    opens with a comment whose SUBJECT is the library and a version; the
    library's own identifier occurs at least three times after it; the file is
    as big as a library is (8 KiB) and its body reads no HTTP request and
    starts no web server. A comment that only mentions a library, or a `/*!`
    banner with any name, is not that (DE4-01): uncertain files are in scope."""
    if size is None:
        size = len(head.encode("utf-8", errors="replace"))
    if size < _VENDOR_MIN_BYTES:
        return None
    comment = _leading_comment(head)
    if not comment:
        return None
    text = _banner_text(comment)
    at = head.find(comment)
    body = head[at + len(comment):] if at >= 0 else head
    for name, subject, ident in _VENDOR_LIBRARIES:
        if not subject.match(text):
            continue
        hits = 0
        for _ in ident.finditer(body):
            hits += 1
            if hits >= _VENDOR_BODY_HITS:
                break
        if hits < _VENDOR_BODY_HITS:
            continue
        return None if _REQUEST_USE.search(body) else name
    return None


def minified_statistics(text: str) -> Optional[str]:
    """The measurement that makes `text` minified, or None (go: `isMinified`):
    at least 90% of its bytes on lines over 250 bytes, those lines at least
    1 KiB, at least one byte in twenty of them one of ; { } ( ) =, and no more
    than 40 other non-blank lines. A short file, a file of ordinary lines, a
    long line of prose or data and a base64 blob among hundreds of code lines
    are never minified by this."""
    data = text.encode("utf-8", errors="replace")[:HEAD_BYTES]
    total = len(data)
    if total < MINIFIED_MIN_LONG_BYTES:
        return None
    long_bytes = short = syntax = 0
    for line in data.split(b"\n"):
        n = len(line.rstrip(b"\r"))
        if n > MINIFIED_LONG_LINE:
            long_bytes += n
            syntax += sum(line.count(c) for c in b";{}()=")
        elif n > 0:
            short += 1
            if short > MINIFIED_MAX_SHORT_LINES:
                return None
    if (
        long_bytes < MINIFIED_MIN_LONG_BYTES
        or long_bytes * 10 < total * 9
        or syntax * MINIFIED_SYNTAX_ONE_IN < long_bytes
    ):
        return None
    return (
        f"minified: {round(100 * long_bytes / total)}% of bytes on lines over "
        f"{MINIFIED_LONG_LINE}, {round(100 * syntax / long_bytes)}% syntax"
    )


def compiled_output(head: str, tail: Optional[str] = None) -> Optional[str]:
    """"compiled output" for a webpack bootstrap in the head or a trailing
    `//# sourceMappingURL=` comment (go: `isCompiledOutput`), else None."""
    if _WEBPACK_BOOT.search(head):
        return "compiled output: webpack bootstrap"
    probe = tail if tail else head
    if _SOURCE_MAP_REF.search(probe):
        return "compiled output: sourceMappingURL"
    return None


def file_evidence(
    text: str,
    size: Optional[int] = None,
    tail: Optional[str] = None,
    under_cap: bool = False,
) -> Optional[str]:
    """Why `text` (a JavaScript or TypeScript file's content) is minified, a
    well-known vendored library, generated or compiled output, or None when
    nothing deterministic says so. The checks and their order are
    go/internal/scope `ClassifyFile`. With `under_cap` (the file is within the
    size cap and would be analysed) only minified and vendored evidence leaves
    it out, as `Verdict.ExcludableUnderCap` does: a generated or compiled file
    under the cap is still scanned, since leaving it out would weaken
    detection. The reason is short enough for a status detail."""
    head = _head_text(text)
    stats = minified_statistics(head)
    if stats:
        return stats
    library = library_banner(head, size)
    if library:
        return f"vendored library: {library}"
    if under_cap:
        return None
    if generated_marker(head):
        return "generated: generator header"
    return compiled_output(head, tail)


def _read_small(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > _MAX_EVIDENCE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _record_top_level(record_text: str) -> set:
    """The top-level entries a dist-info RECORD names (`pkg/`, `six.py`)."""
    top = set()
    for row in csv.reader(io.StringIO(record_text)):
        if not row:
            continue
        first = row[0].replace("\\", "/")
        if first.startswith(("/", "..")) or not first:
            continue
        name = first.split("/")[0]
        if name.endswith(".dist-info"):
            continue  # the metadata directory is not an installed package
        top.add(name)
    return top


def _npm_package(path: Path) -> bool:
    text = _read_small(path / "package.json")
    if text is None:
        return False
    try:
        data = json.loads(text)
    except ValueError:
        return False
    return (
        isinstance(data, dict)
        and isinstance(data.get("name"), str)
        and bool(data["name"])
        and isinstance(data.get("version"), str)
        and bool(data["version"])
    )


class SourceWalk:
    """One walk of the scan root that every pass of the Python engine shares
    (the route index, the call index and the analysis), so they agree on what
    is in scope. It prunes the directories that D6' evidence marks as not the
    project's own code, notes every one (and every symlink it does not follow)
    in `declared`, and notes every directory it cannot list in `lost`."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.declared: List[Entry] = []
        self.lost: List[Entry] = []
        self._groups: Dict[Tuple[str, str], int] = {}
        # dirpath -> {child directory: ("silent" | "single" | "group:<key>", why)}
        self._classified: Dict[str, Dict[str, Tuple[str, str]]] = {}
        # dirpath -> the top-level names its dist-info RECORDs claim
        self._claimed: Dict[str, set] = {}

    # ---- classification ----------------------------------------------

    def _classify(self, dirpath: str, dirnames: List[str]) -> Dict[str, Tuple[str, str]]:
        cached = self._classified.get(dirpath)
        if cached is not None:
            return cached
        base = Path(dirpath)
        claimed: set = set()
        for child in dirnames:
            if child.endswith(".dist-info"):
                record = _read_small(base / child / "RECORD")
                if record is not None:
                    claimed |= _record_top_level(record)
        in_node_modules = base.name == "node_modules"
        out: Dict[str, Tuple[str, str]] = {}
        for child in dirnames:
            path = base / child
            try:
                linked = path.is_symlink()
            except OSError:
                linked = False
            if linked:
                out[child] = ("single", "symlink, not followed")
            elif child == ".git" and (path / "HEAD").is_file():
                out[child] = ("silent", "git metadata")
            elif (path / "pyvenv.cfg").is_file():
                out[child] = ("single", "virtualenv: pyvenv.cfg")
            elif child in claimed:
                out[child] = ("group:installed", "installed")
            elif (
                in_node_modules
                and not child.startswith((".", "@"))
                and _npm_package(path)
            ):
                out[child] = ("group:npm", "npm")
        self._classified[dirpath] = out
        self._claimed[dirpath] = claimed
        return out

    # ---- the walk -------------------------------------------------------

    def walk(self, record: bool = False) -> Iterator[Tuple[str, List[str]]]:
        """`(dirpath, filenames)` for every directory in scope, in a stable
        order. With `record`, what is left out is noted in `declared` and
        `lost`; the other passes walk the same tree without noting it again."""

        def unreadable(exc: OSError) -> None:
            if not record:
                return
            where = Path(exc.filename) if exc.filename else self.root
            try:
                rel_dir = str(where.relative_to(self.root)) or "."
            except ValueError:
                rel_dir = str(where)
            self.lost.append(
                (rel_dir if rel_dir == "." else rel_dir + "/", f"directory unreadable: {type(exc).__name__}")
            )

        for dirpath, dirnames, filenames in os.walk(self.root, onerror=unreadable):
            dirnames.sort()
            filenames.sort()
            verdicts = self._classify(dirpath, dirnames)
            kept = []
            for child in dirnames:
                verdict = verdicts.get(child)
                if verdict is None:
                    kept.append(child)
                    continue
                if not record:
                    continue
                kind, why = verdict
                rel = os.path.relpath(os.path.join(dirpath, child), self.root)
                if kind == "single":
                    self.declared.append((rel + "/", why))
                elif kind.startswith("group:"):
                    parent = os.path.relpath(dirpath, self.root)
                    key = (parent, kind.split(":", 1)[1])
                    self._groups[key] = self._groups.get(key, 0) + 1
            dirnames[:] = kept
            claimed = self._claimed.get(dirpath) or set()
            if claimed:
                # A file a dist-info RECORD lists (`six.py`) is installed code
                # as much as a package directory it lists is.
                installed = [f for f in filenames if f in claimed]
                if installed:
                    if record:
                        parent = os.path.relpath(dirpath, self.root)
                        key = (parent, "installed")
                        self._groups[key] = self._groups.get(key, 0) + len(installed)
                    filenames = [f for f in filenames if f not in claimed]
            yield dirpath, filenames

    def finish(self) -> None:
        """Turn the per-directory package counts into declared entries. Call
        once, after the recording walk."""
        notes = {
            "installed": "installed Python package(s), named by a dist-info RECORD",
            "npm": "npm package(s), package.json name and version",
        }
        for (parent, kind), count in sorted(self._groups.items()):
            where = "./" if parent == "." else parent.rstrip("/") + "/"
            self.declared.append((where, f"{count} {notes[kind]}"))
        self._groups = {}

