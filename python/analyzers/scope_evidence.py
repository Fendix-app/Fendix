"""What the Python engine may leave unread, and the evidence that says so (D5-2).

One rule, the Go engine's (`go/internal/scope`): every supported in-scope file
at or below the size cap is analysed, whatever its content looks like. The
engine used to leave a file out when its first 64 KiB looked minified, when it
opened with a library banner or a generator header, and a directory when it held
a `pyvenv.cfg`, a dist-info RECORD or an npm `package.json`. Each of those is
text anyone can write, so each one let a repository hide code from the scan, and
the scan still read complete (post-commit review items 1 and 2, C4B-02, C4B-03).
None of it is evidence, and none of it is used.

What is left out of the walk:

* a symlink, never followed (a link out of the scan root would read content the
  repository does not hold). It is listed, as `symbolic link`;
* the version-control metadata directory at the scan root, `<root>/.git`, and
  only when its layout is real: a regular `HEAD` file next to real `objects/`
  and `refs/` directories. A `.git` anywhere else, or one without that layout,
  is ordinary content and is walked. The probe is three `lstat` calls: it opens
  nothing, so a named pipe or a link planted in place of a marker cannot block
  it or send it out of the root.

No dependency tree is left out (owner amendment A1 to D5-2). Every scheme that could
prove a directory is an unmodified third-party package rests on a hash the
repository itself writes (go.sum, a package lock, a dist-info RECORD), and the
scan is offline, so none can be checked against an authority outside the
repository. A forged pin would hide first-party code and credentials from a scan
that reads complete. A directory named `x@v1.2.3`, a `vendor` tree,
`node_modules` and `site-packages` are walked like any other directory.

Everything else is walked, including `node_modules`, virtualenvs,
`site-packages`, `vendor`, `build`, `dist`, test and fixture trees, and minified,
vendored and generated files. The one content-based exclusion in the Go engine,
a recognised lockfile (a closed list of basenames whose content parses as that
format), concerns files the Python engine never reads: it analyses `.py` and the
JavaScript family only, and no lockfile has one of those suffixes.

A file the engine could not read is lost evaluation, never a clean result: one
over the size cap, one it cannot open, one that is not a regular file (a named
pipe, a device), a directory it cannot list. `ast_analyzer` records each with
its reason; this module records the directories (`SourceWalk.lost`).
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Iterator, List, Tuple

Entry = Tuple[str, str]  # (path, reason)

# The name of the version-control metadata directory the engine skips at the
# scan root, and the entries whose presence, as real files or directories,
# make its layout real.
GIT_DIR = ".git"

# Why a symlink is listed as left out: the wording of `go/internal/scope`
# (`ReasonSymlink`), so one link reads the same from every analyzer.
SYMLINK_REASON = "symbolic link"


def _lstat_mode(path: str) -> int | None:
    try:
        return os.lstat(path).st_mode
    except OSError:
        return None


def is_regular_file(path: Path | str) -> bool:
    """True when `path` is a regular file and not a symlink, named pipe, socket
    or device. `lstat` never opens the path, so asking cannot block."""
    mode = _lstat_mode(str(path))
    return mode is not None and stat.S_ISREG(mode)


class NotRegularFile(OSError):
    """`read_regular` opened a path that is not a regular file."""

    def __init__(self, path: Path | str) -> None:
        super().__init__(errno.EINVAL, "not a regular file", str(path))


def read_regular(path: Path | str) -> bytes:
    """The bytes of the regular file at `path`. The file is opened without
    following a symlink and without blocking (`O_NOFOLLOW`, `O_NONBLOCK`, where
    the platform has them) and is then checked to be a regular file, so a named
    pipe or a link swapped in after the walk listed the name can neither stall
    the scan nor send it out of the root. Raises `NotRegularFile` for anything
    else and `OSError` when it cannot be read."""
    flags = os.O_RDONLY
    for name in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    fd = os.open(str(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile(path)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(fd)


def is_git_metadata(path: Path | str) -> bool:
    """True when `path` has the layout of a real Git directory: a regular
    `HEAD` file and `objects` and `refs` directories, none of them a link."""
    base = str(path)
    head = _lstat_mode(os.path.join(base, "HEAD"))
    objects = _lstat_mode(os.path.join(base, "objects"))
    refs = _lstat_mode(os.path.join(base, "refs"))
    return (
        head is not None
        and stat.S_ISREG(head)
        and objects is not None
        and stat.S_ISDIR(objects)
        and refs is not None
        and stat.S_ISDIR(refs)
    )


class SourceWalk:
    """One walk of the scan root that every pass of the Python engine shares
    (the route index, the call index and the analysis), so they agree on what
    is in scope. It prunes only a symlinked directory and a real `<root>/.git`,
    notes every symlink it does not follow in `declared`, and notes every
    directory it cannot list in `lost`."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.declared: List[Entry] = []
        self.lost: List[Entry] = []

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
            at_root = Path(dirpath) == self.root
            kept = []
            for child in dirnames:
                path = os.path.join(dirpath, child)
                mode = _lstat_mode(path)
                if mode is not None and stat.S_ISLNK(mode):
                    # Not followed, and said so.
                    if record:
                        self.declared.append((os.path.relpath(path, self.root) + "/", SYMLINK_REASON))
                    continue
                if at_root and child == GIT_DIR and is_git_metadata(path):
                    continue
                kept.append(child)
            dirnames[:] = kept
            yield dirpath, filenames
