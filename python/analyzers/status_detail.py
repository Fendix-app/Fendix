"""The text of a Python-engine status detail, fitted to the byte budget.

The Go side records a status line's `detail` into the report's scanner status
and cuts it at 240 bytes with a trailing "…" (`truncateDetail`). Two readers
take that cut as a signal (the backend's classifier and the frontend's coverage
strip), and neither can tell a cut LISTING from a lost one, so this module never
lets the Go side cut a detail: every detail the Python engine writes is built
here, within `DETAIL_BUDGET` bytes, by the rules below (cross-owner contracts
C1 and C2).

C1, safe segments. A detail is segments joined by "; ". Any file name or other
repository-controlled string put in one is made safe by `clean`: ';', '…',
control characters and line breaks become '?', and the string is cut to
`MAX_NAME_BYTES` bytes. A segment that lists what was left out on purpose
starts with `DECLARED_MARKER` exactly; readers do not look for loss patterns
inside it, so a file named like a loss message cannot change the verdict.

C2, no half-written listing. The segments are written in priority order: the
lead note (what the check did), then loss (`LOSS_PREFIX`, what was not
evaluated), then the declared exclusions. A listing names as many entries as
fit and ends with "and N more (see report metadata)"; the count is always
kept. The complete lists travel in the status line's additive `scope` field
(`scope_payload`), which the Go side can copy into the report metadata.
"""

from __future__ import annotations

from typing import Optional, Sequence

# The Go bound on a scanner-status detail (`detailMax` in
# go/internal/engine/scannerstatus.go). A longer detail is cut with "…".
DETAIL_BUDGET = 240

# The longest a repository-controlled name may be in a detail, in bytes.
MAX_NAME_BYTES = 80

LOSS_PREFIX = "lost evaluation: "
DECLARED_MARKER = "declared out of scope, not scanned:"
SEE_METADATA = "see report metadata"

# How many entries one listing names at most; the rest are counted.
_MAX_LISTED = 5

# How many entries the complete lists in `scope_payload` hold at most.
_MAX_PAYLOAD_ENTRIES = 1000
_MAX_PAYLOAD_NAME_BYTES = 300

Entry = tuple[str, str]  # (path, reason)


def clean(text: str, limit: int = MAX_NAME_BYTES) -> str:
    """`text` made safe for one segment of a detail (C1): ';', '…', control
    characters and line breaks become '?', and it is cut to `limit` bytes
    (never inside a character)."""
    out = []
    for ch in str(text):
        if ch in ";…" or ord(ch) < 0x20 or ord(ch) == 0x7F or 0x80 <= ord(ch) < 0xA0:
            out.append("?")
        elif ch in "  ":
            out.append("?")
        else:
            out.append(ch)
    cleaned = "".join(out)
    data = cleaned.encode("utf-8")
    if len(data) <= limit:
        return cleaned
    return data[:limit].decode("utf-8", errors="ignore")


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _size(text: str) -> int:
    return len(text.encode("utf-8"))


def _listing(entries: Sequence[Entry], k: int) -> str:
    """The first `k` entries as "a (why), b (why)", then "and N more (see
    report metadata)" for the rest. k=0 gives just the pointer."""
    n = len(entries)
    shown = ", ".join(f"{clean(path)} ({clean(why)})" for path, why in entries[:k])
    rest = n - k
    if k == 0:
        return f"({SEE_METADATA})"
    if rest > 0:
        return f"{shown} and {rest} more ({SEE_METADATA})"
    return shown


def loss_segment(entries: Sequence[Entry], k: int, pointer: bool = True) -> str:
    """The lost-evaluation segment naming the first `k` files. With k=0 it is
    the count and, when `pointer`, the metadata pointer; `pointer=False` is the
    shortest form, the kind and the count alone."""
    files = _group(entries)
    head = f"{LOSS_PREFIX}{_plural(len(files), 'in-scope file')} not fully analysed"
    if k == 0:
        return f"{head} ({SEE_METADATA})" if pointer else head
    return f"{head}: {_listing(files, k)}"


def declared_segment(entries: Sequence[Entry], k: int, pointer: bool = True) -> str:
    """The declared-exclusions segment naming the first `k` paths. Starts with
    `DECLARED_MARKER`, in every form (C1). With k=0 it is the count and, when
    `pointer`, the metadata pointer; `pointer=False` is the marker and the
    count alone."""
    head = f"{DECLARED_MARKER} {_plural(len(entries), 'path')}"
    if k == 0:
        return f"{head} ({SEE_METADATA})" if pointer else head
    return f"{head}: {_listing(entries, k)}"


def _group(entries: Sequence[Entry]) -> list[Entry]:
    """One entry per file, in first-seen order, its distinct reasons joined by
    " + " (';' is reserved for segment breaks)."""
    reasons: dict[str, list[str]] = {}
    for path, reason in entries:
        bucket = reasons.setdefault(path, [])
        if reason not in bucket:
            bucket.append(reason)
    return [(path, " + ".join(rs)) for path, rs in reasons.items()]


def fit(
    lead: Sequence[str] = (),
    loss: Sequence[Entry] = (),
    declared: Sequence[Entry] = (),
    budget: int = DETAIL_BUDGET,
) -> str:
    """The detail for a check: `lead` segments as given, then the loss
    segment, then the declared segment, joined by "; ", within `budget` bytes.
    Loss names are given room first, then declared names. Nothing is cut: a
    listing that does not fit names fewer entries and gives the count."""
    lead_text = [s for s in lead if s]
    n_loss = len(_group(loss)) if loss else 0
    n_decl = len(declared)

    def build(k_loss: int, k_decl: int, pointer: bool = True, lead_n: int = -1) -> str:
        parts = list(lead_text if lead_n < 0 else lead_text[:lead_n])
        if n_loss:
            parts.append(loss_segment(loss, k_loss, pointer))
        if n_decl:
            parts.append(declared_segment(declared, k_decl, pointer))
        return "; ".join(parts)

    # Loss first: the most names that leave the declared segment its counts.
    k_loss = min(n_loss, _MAX_LISTED)
    while k_loss > 0 and _size(build(k_loss, 0)) > budget:
        k_loss -= 1
    k_decl = min(n_decl, _MAX_LISTED)
    while k_decl > 0 and _size(build(k_loss, k_decl)) > budget:
        k_decl -= 1
    text = build(k_loss, k_decl)
    if _size(text) <= budget:
        return text
    # Even the counts do not fit: the kind and the count of each segment are
    # kept (C2: the marker and the count are never lost); the pointer goes
    # first, then lead notes from the last, never a loss or declared segment.
    text = build(0, 0, pointer=False)
    if _size(text) <= budget:
        return text
    for lead_n in range(len(lead_text) - 1, -1, -1):
        text = build(0, 0, pointer=False, lead_n=lead_n)
        if _size(text) <= budget:
            return text
    return text


def scope_payload(
    lost: Sequence[Entry], declared: Sequence[Entry]
) -> Optional[dict]:
    """The complete lists, for the status line's additive `scope` field: the
    files whose analysis was lost and the paths left out on purpose, each as
    `[path, reason]`, cut at `_MAX_PAYLOAD_ENTRIES` entries each (`truncated`
    says so). None when both are empty."""
    if not lost and not declared:
        return None

    def rows(entries: Sequence[Entry]) -> list[list[str]]:
        return [
            [
                clean(path, _MAX_PAYLOAD_NAME_BYTES),
                clean(why, _MAX_PAYLOAD_NAME_BYTES),
            ]
            for path, why in entries[:_MAX_PAYLOAD_ENTRIES]
        ]

    payload: dict = {"lost": rows(lost), "declared": rows(declared)}
    if len(lost) > _MAX_PAYLOAD_ENTRIES or len(declared) > _MAX_PAYLOAD_ENTRIES:
        payload["truncated"] = True
    return payload
