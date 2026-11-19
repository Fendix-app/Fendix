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
import json
import os
import stat
from pathlib import Path
from typing import Iterator, List, NamedTuple, Optional, Tuple

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


# ---------------------------------------------------------------------------
# PEP 263: is the text the engine reads the program CPython runs? (Round 6,
# WS-E1: R5-01, R6-E1, R6-E6.) The same predicate as go/internal/scope/
# pysource.go, driven by the same generated codec table, and pinned by the
# vectors in go/internal/scope/testdata (python/tests/test_pep263_vectors.py).
#
# CPython reads a cookie (`coding[:=]name` in a comment-only line) from line 1,
# or from line 2 when line 1 is blank or a comment, with lines ended by \r\n, \r
# or \n and no byte limit; `python -x` skips line 1 up to its \n, so a cookie on
# line 2 counts whatever line 1 holds. A UTF-8 byte-order mark with a cookie
# naming anything but utf-8 is refused. The name is resolved as CPython does:
# the tokenizer's get_normal_name, then the codec registry, whose alias table and
# modules the generated table carries.
#
# Verdicts: plain (no cookie), transparent (an ASCII-transparent codec: read as
# UTF-8), foreign (a codec CPython knows that is not: the Python engine decodes
# with it, Semgrep and secrets lose the file), unknown (no codec in a fresh
# interpreter, which only a run-time registration could supply: lost
# everywhere), refused (CPython refuses the file: nothing runs).
# ---------------------------------------------------------------------------

# The codec policy: the owner's D2-A (OWNER-DECISIONS §0.8, approved in the
# Release Closure Sprint, OR-85). Only the takeover-immune spellings of utf-8,
# latin-1 and ascii stay UTF-8-equivalent; every other cookie is foreign (a
# module in the scanned repository can rebind any other name at run time by
# writing encodings._cache). "d2" is D2 as first approved, a documented false
# clean, kept so that a tree can be built to reproduce it. The Go constant
# codecPolicy (go/internal/scope/pysource.go) must say the same.
PEP263_POLICY = "d2a"

# BEGIN GENERATED PEP263 CODEC TABLE (gen_pep263_vectors.py --sync-python; do not edit)
_PEP263_CODEC_TABLE_JSON = r'''{"about":"PEP 263 codec table for scope.ClassifyPythonSource (Go, embedded) and scope_evidence.python_source_encoding (Python, copied). Generated by gen_pep263_vectors.py from CPython 3.14.5; never edited by hand.","aliases":{"037":"cp037","1026":"cp1026","1125":"cp1125","1140":"cp1140","1250":"cp1250","1251":"cp1251","1252":"cp1252","1253":"cp1253","1254":"cp1254","1255":"cp1255","1256":"cp1256","1257":"cp1257","1258":"cp1258","273":"cp273","424":"cp424","437":"cp437","500":"cp500","646":"ascii","775":"cp775","850":"cp850","852":"cp852","855":"cp855","857":"cp857","858":"cp858","860":"cp860","861":"cp861","862":"cp862","863":"cp863","864":"cp864","865":"cp865","866":"cp866","869":"cp869","874":"cp874","8859":"latin_1","932":"cp932","936":"gbk","949":"cp949","950":"cp950","ansi":"mbcs","ansi_x3.4_1968":"ascii","ansi_x3.4_1986":"ascii","ansi_x3_4_1968":"ascii","arabic":"iso8859_6","asmo_708":"iso8859_6","base64":"base64_codec","base_64":"base64_codec","big5_hkscs":"big5hkscs","big5_tw":"big5","bz2":"bz2_codec","chinese":"gb2312","cp1051":"hp_roman8","cp1361":"johab","cp154":"ptcp154","cp367":"ascii","cp65001":"utf_8","cp819":"latin_1","cp866u":"cp1125","cp936":"gbk","cp_gr":"cp869","cp_is":"cp861","csHPRoman8":"hp_roman8","csascii":"ascii","csbig5":"big5","cseuckr":"euc_kr","csibm037":"cp037","csibm1026":"cp1026","csibm273":"cp273","csibm424":"cp424","csibm500":"cp500","csibm855":"cp855","csibm857":"cp857","csibm858":"cp858","csibm860":"cp860","csibm861":"cp861","csibm863":"cp863","csibm864":"cp864","csibm865":"cp865","csibm866":"cp866","csibm869":"cp869","csiso2022jp":"iso2022_jp","csiso2022kr":"iso2022_kr","csiso58gb231280":"gb2312","csisolatin1":"latin_1","csisolatin2":"iso8859_2","csisolatin3":"iso8859_3","csisolatin4":"iso8859_4","csisolatin5":"iso8859_9","csisolatin6":"iso8859_10","csisolatinarabic":"iso8859_6","csisolatincyrillic":"iso8859_5","csisolatingreek":"iso8859_7","csisolatinhebrew":"iso8859_8","cskoi8r":"koi8_r","cspc775baltic":"cp775","cspc850multilingual":"cp850","cspc862latinhebrew":"cp862","cspc8codepage437":"cp437","cspcp852":"cp852","csptcp154":"ptcp154","csshiftjis":"shift_jis","cyrillic":"iso8859_5","cyrillic_asian":"ptcp154","dbcs":"mbcs","ebcdic_cp_be":"cp500","ebcdic_cp_ca":"cp037","ebcdic_cp_ch":"cp500","ebcdic_cp_he":"cp424","ebcdic_cp_nl":"cp037","ebcdic_cp_us":"cp037","ebcdic_cp_wt":"cp037","ecma_114":"iso8859_6","ecma_118":"iso8859_7","elot_928":"iso8859_7","euc_cn":"gb2312","euc_jis2004":"euc_jis_2004","euccn":"gb2312","eucgb2312_cn":"gb2312","eucjis2004":"euc_jis_2004","eucjisx0213":"euc_jisx0213","eucjp":"euc_jp","euckr":"euc_kr","gb18030_2000":"gb18030","gb2312_1980":"gb2312","gb2312_80":"gb2312","greek":"iso8859_7","greek8":"iso8859_7","hebrew":"iso8859_8","hex":"hex_codec","hkscs":"big5hkscs","hz_gb":"hz","hz_gb_2312":"hz","hzgb":"hz","ibm037":"cp037","ibm039":"cp037","ibm1026":"cp1026","ibm1051":"hp_roman8","ibm1125":"cp1125","ibm1140":"cp1140","ibm273":"cp273","ibm367":"ascii","ibm424":"cp424","ibm437":"cp437","ibm500":"cp500","ibm775":"cp775","ibm819":"latin_1","ibm850":"cp850","ibm852":"cp852","ibm855":"cp855","ibm857":"cp857","ibm858":"cp858","ibm860":"cp860","ibm861":"cp861","ibm862":"cp862","ibm863":"cp863","ibm864":"cp864","ibm865":"cp865","ibm866":"cp866","ibm869":"cp869","iso2022jp":"iso2022_jp","iso2022jp_1":"iso2022_jp_1","iso2022jp_2":"iso2022_jp_2","iso2022jp_2004":"iso2022_jp_2004","iso2022jp_3":"iso2022_jp_3","iso2022jp_ext":"iso2022_jp_ext","iso2022kr":"iso2022_kr","iso646_us":"ascii","iso8859":"latin_1","iso8859_1":"latin_1","iso_2022_jp":"iso2022_jp","iso_2022_jp_1":"iso2022_jp_1","iso_2022_jp_2":"iso2022_jp_2","iso_2022_jp_2004":"iso2022_jp_2004","iso_2022_jp_3":"iso2022_jp_3","iso_2022_jp_ext":"iso2022_jp_ext","iso_2022_kr":"iso2022_kr","iso_646.irv_1991":"ascii","iso_8859_1":"latin_1","iso_8859_10":"iso8859_10","iso_8859_10_1992":"iso8859_10","iso_8859_11":"iso8859_11","iso_8859_11_2001":"iso8859_11","iso_8859_13":"iso8859_13","iso_8859_14":"iso8859_14","iso_8859_14_1998":"iso8859_14","iso_8859_15":"iso8859_15","iso_8859_16":"iso8859_16","iso_8859_16_2001":"iso8859_16","iso_8859_1_1987":"latin_1","iso_8859_2":"iso8859_2","iso_8859_2_1987":"iso8859_2","iso_8859_3":"iso8859_3","iso_8859_3_1988":"iso8859_3","iso_8859_4":"iso8859_4","iso_8859_4_1988":"iso8859_4","iso_8859_5":"iso8859_5","iso_8859_5_1988":"iso8859_5","iso_8859_6":"iso8859_6","iso_8859_6_1987":"iso8859_6","iso_8859_7":"iso8859_7","iso_8859_7_1987":"iso8859_7","iso_8859_8":"iso8859_8","iso_8859_8_1988":"iso8859_8","iso_8859_8_e":"iso8859_8","iso_8859_8_i":"iso8859_8","iso_8859_9":"iso8859_9","iso_8859_9_1989":"iso8859_9","iso_celtic":"iso8859_14","iso_ir_100":"latin_1","iso_ir_101":"iso8859_2","iso_ir_109":"iso8859_3","iso_ir_110":"iso8859_4","iso_ir_126":"iso8859_7","iso_ir_127":"iso8859_6","iso_ir_138":"iso8859_8","iso_ir_144":"iso8859_5","iso_ir_148":"iso8859_9","iso_ir_157":"iso8859_10","iso_ir_166":"tis_620","iso_ir_199":"iso8859_14","iso_ir_226":"iso8859_16","iso_ir_58":"gb2312","iso_ir_6":"ascii","jisx0213":"euc_jis_2004","korean":"euc_kr","ks_c_5601":"euc_kr","ks_c_5601_1987":"euc_kr","ks_x_1001":"euc_kr","ksc5601":"euc_kr","ksx1001":"euc_kr","kz_1048":"kz1048","l1":"latin_1","l10":"iso8859_16","l2":"iso8859_2","l3":"iso8859_3","l4":"iso8859_4","l5":"iso8859_9","l6":"iso8859_10","l7":"iso8859_13","l8":"iso8859_14","l9":"iso8859_15","latin":"latin_1","latin1":"latin_1","latin10":"iso8859_16","latin2":"iso8859_2","latin3":"iso8859_3","latin4":"iso8859_4","latin5":"iso8859_9","latin6":"iso8859_10","latin7":"iso8859_13","latin8":"iso8859_14","latin9":"iso8859_15","mac_centeuro":"mac_latin2","maccentraleurope":"mac_latin2","maccyrillic":"mac_cyrillic","macgreek":"mac_greek","maciceland":"mac_iceland","macintosh":"mac_roman","maclatin2":"mac_latin2","macroman":"mac_roman","macturkish":"mac_turkish","ms1361":"johab","ms874":"cp874","ms932":"cp932","ms936":"gbk","ms949":"cp949","ms950":"cp950","ms_kanji":"cp932","mskanji":"cp932","pt154":"ptcp154","quopri":"quopri_codec","quoted_printable":"quopri_codec","quotedprintable":"quopri_codec","r8":"hp_roman8","rk1048":"kz1048","roman8":"hp_roman8","rot13":"rot_13","ruscii":"cp1125","s_jis":"shift_jis","s_jis_2004":"shift_jis_2004","s_jisx0213":"shift_jisx0213","shiftjis":"shift_jis","shiftjis2004":"shift_jis_2004","shiftjisx0213":"shift_jisx0213","sjis":"shift_jis","sjis_2004":"shift_jis_2004","sjisx0213":"shift_jisx0213","strk1048_2002":"kz1048","thai":"iso8859_11","tis620":"tis_620","tis_620_0":"tis_620","tis_620_2529_0":"tis_620","tis_620_2529_1":"tis_620","u16":"utf_16","u32":"utf_32","u7":"utf_7","u8":"utf_8","u_jis":"euc_jp","uhc":"cp949","ujis":"euc_jp","unicode_1_1_utf_7":"utf_7","unicodebigunmarked":"utf_16_be","unicodelittleunmarked":"utf_16_le","us":"ascii","us_ascii":"ascii","utf":"utf_8","utf16":"utf_16","utf32":"utf_32","utf7":"utf_7","utf8":"utf_8","utf8_ucs2":"utf_8","utf8_ucs4":"utf_8","utf_16be":"utf_16_be","utf_16le":"utf_16_le","utf_32be":"utf_32_be","utf_32le":"utf_32_le","uu":"uu_codec","windows_1250":"cp1250","windows_1251":"cp1251","windows_1252":"cp1252","windows_1253":"cp1253","windows_1254":"cp1254","windows_1255":"cp1255","windows_1256":"cp1256","windows_1257":"cp1257","windows_1258":"cp1258","windows_31j":"cp932","windows_874":"cp874","x_mac_japanese":"shift_jis","x_mac_korean":"euc_kr","x_mac_simp_chinese":"gb2312","x_mac_trad_chinese":"big5","zip":"zlib_codec","zlib":"zlib_codec"},"fast_path_normal_forms":["ascii","iso8859_1","latin1","us_ascii","utf8"],"modules":{"ascii":{"class":"transparent","codec":"ascii"},"base64_codec":{"class":"refused","codec":"base64"},"big5":{"class":"foreign","codec":"big5"},"big5hkscs":{"class":"foreign","codec":"big5hkscs"},"bz2_codec":{"class":"refused","codec":"bz2"},"charmap":{"class":"transparent","codec":"charmap"},"cp037":{"class":"foreign","codec":"cp037"},"cp1006":{"class":"transparent","codec":"cp1006"},"cp1026":{"class":"foreign","codec":"cp1026"},"cp1125":{"class":"transparent","codec":"cp1125"},"cp1140":{"class":"foreign","codec":"cp1140"},"cp1250":{"class":"transparent","codec":"cp1250"},"cp1251":{"class":"transparent","codec":"cp1251"},"cp1252":{"class":"transparent","codec":"cp1252"},"cp1253":{"class":"transparent","codec":"cp1253"},"cp1254":{"class":"transparent","codec":"cp1254"},"cp1255":{"class":"transparent","codec":"cp1255"},"cp1256":{"class":"transparent","codec":"cp1256"},"cp1257":{"class":"transparent","codec":"cp1257"},"cp1258":{"class":"transparent","codec":"cp1258"},"cp273":{"class":"foreign","codec":"cp273"},"cp424":{"class":"foreign","codec":"cp424"},"cp437":{"class":"transparent","codec":"cp437"},"cp500":{"class":"foreign","codec":"cp500"},"cp720":{"class":"transparent","codec":"cp720"},"cp737":{"class":"transparent","codec":"cp737"},"cp775":{"class":"transparent","codec":"cp775"},"cp850":{"class":"transparent","codec":"cp850"},"cp852":{"class":"transparent","codec":"cp852"},"cp855":{"class":"transparent","codec":"cp855"},"cp856":{"class":"transparent","codec":"cp856"},"cp857":{"class":"transparent","codec":"cp857"},"cp858":{"class":"transparent","codec":"cp858"},"cp860":{"class":"transparent","codec":"cp860"},"cp861":{"class":"transparent","codec":"cp861"},"cp862":{"class":"transparent","codec":"cp862"},"cp863":{"class":"transparent","codec":"cp863"},"cp864":{"class":"foreign","codec":"cp864"},"cp865":{"class":"transparent","codec":"cp865"},"cp866":{"class":"transparent","codec":"cp866"},"cp869":{"class":"transparent","codec":"cp869"},"cp874":{"class":"transparent","codec":"cp874"},"cp875":{"class":"foreign","codec":"cp875"},"cp932":{"class":"foreign","codec":"cp932"},"cp949":{"class":"foreign","codec":"cp949"},"cp950":{"class":"foreign","codec":"cp950"},"euc_jis_2004":{"class":"transparent","codec":"euc_jis_2004"},"euc_jisx0213":{"class":"transparent","codec":"euc_jisx0213"},"euc_jp":{"class":"transparent","codec":"euc_jp"},"euc_kr":{"class":"transparent","codec":"euc_kr"},"gb18030":{"class":"foreign","codec":"gb18030"},"gb2312":{"class":"transparent","codec":"gb2312"},"gbk":{"class":"foreign","codec":"gbk"},"hex_codec":{"class":"refused","codec":"hex"},"hp_roman8":{"class":"transparent","codec":"hp-roman8"},"hz":{"class":"foreign","codec":"hz"},"idna":{"class":"foreign","codec":"idna"},"iso2022_jp":{"class":"foreign","codec":"iso2022_jp"},"iso2022_jp_1":{"class":"foreign","codec":"iso2022_jp_1"},"iso2022_jp_2":{"class":"foreign","codec":"iso2022_jp_2"},"iso2022_jp_2004":{"class":"foreign","codec":"iso2022_jp_2004"},"iso2022_jp_3":{"class":"foreign","codec":"iso2022_jp_3"},"iso2022_jp_ext":{"class":"foreign","codec":"iso2022_jp_ext"},"iso2022_kr":{"class":"foreign","codec":"iso2022_kr"},"iso8859_1":{"class":"transparent","codec":"iso8859-1"},"iso8859_10":{"class":"transparent","codec":"iso8859-10"},"iso8859_11":{"class":"transparent","codec":"iso8859-11"},"iso8859_13":{"class":"transparent","codec":"iso8859-13"},"iso8859_14":{"class":"transparent","codec":"iso8859-14"},"iso8859_15":{"class":"transparent","codec":"iso8859-15"},"iso8859_16":{"class":"transparent","codec":"iso8859-16"},"iso8859_2":{"class":"transparent","codec":"iso8859-2"},"iso8859_3":{"class":"transparent","codec":"iso8859-3"},"iso8859_4":{"class":"transparent","codec":"iso8859-4"},"iso8859_5":{"class":"transparent","codec":"iso8859-5"},"iso8859_6":{"class":"transparent","codec":"iso8859-6"},"iso8859_7":{"class":"transparent","codec":"iso8859-7"},"iso8859_8":{"class":"transparent","codec":"iso8859-8"},"iso8859_9":{"class":"transparent","codec":"iso8859-9"},"johab":{"class":"foreign","codec":"johab"},"koi8_r":{"class":"transparent","codec":"koi8-r"},"koi8_t":{"class":"transparent","codec":"koi8-t"},"koi8_u":{"class":"transparent","codec":"koi8-u"},"kz1048":{"class":"transparent","codec":"kz1048"},"latin_1":{"class":"transparent","codec":"iso8859-1"},"mac_arabic":{"class":"foreign","codec":"mac-arabic"},"mac_croatian":{"class":"transparent","codec":"mac-croatian"},"mac_cyrillic":{"class":"transparent","codec":"mac-cyrillic"},"mac_farsi":{"class":"foreign","codec":"mac-farsi"},"mac_greek":{"class":"transparent","codec":"mac-greek"},"mac_iceland":{"class":"transparent","codec":"mac-iceland"},"mac_latin2":{"class":"transparent","codec":"mac-latin2"},"mac_roman":{"class":"transparent","codec":"mac-roman"},"mac_romanian":{"class":"transparent","codec":"mac-romanian"},"mac_turkish":{"class":"transparent","codec":"mac-turkish"},"palmos":{"class":"transparent","codec":"palmos"},"ptcp154":{"class":"transparent","codec":"ptcp154"},"punycode":{"class":"foreign","codec":"punycode"},"quopri_codec":{"class":"refused","codec":"quopri"},"raw_unicode_escape":{"class":"foreign","codec":"raw-unicode-escape"},"rot_13":{"class":"refused","codec":"rot-13"},"shift_jis":{"class":"foreign","codec":"shift_jis"},"shift_jis_2004":{"class":"foreign","codec":"shift_jis_2004"},"shift_jisx0213":{"class":"foreign","codec":"shift_jisx0213"},"tis_620":{"class":"transparent","codec":"tis-620"},"undefined":{"class":"refused","codec":"undefined"},"unicode_escape":{"class":"foreign","codec":"unicode-escape"},"utf_16":{"class":"foreign","codec":"utf-16"},"utf_16_be":{"class":"foreign","codec":"utf-16-be"},"utf_16_le":{"class":"foreign","codec":"utf-16-le"},"utf_32":{"class":"foreign","codec":"utf-32"},"utf_32_be":{"class":"foreign","codec":"utf-32-be"},"utf_32_le":{"class":"foreign","codec":"utf-32-le"},"utf_7":{"class":"foreign","codec":"utf-7"},"utf_8":{"class":"transparent","codec":"utf-8"},"utf_8_sig":{"class":"transparent","codec":"utf-8-sig"},"uu_codec":{"class":"refused","codec":"uu"},"zlib_codec":{"class":"refused","codec":"zlib"}},"schema":1}'''
# END GENERATED PEP263 CODEC TABLE

_PEP263_TABLE = json.loads(_PEP263_CODEC_TABLE_JSON)
_PEP263_ALIASES = _PEP263_TABLE.get("aliases", {})
_PEP263_MODULES = _PEP263_TABLE.get("modules", {})
_PEP263_FAST = frozenset(_PEP263_TABLE.get("fast_path_normal_forms", ()))
_BOM = b"\xef\xbb\xbf"
_RANK = {"plain": 0, "transparent": 1, "refused": 2, "foreign": 3, "unknown": 4, "undeterminable": 5}


class SourceEncoding(NamedTuple):
    """What CPython makes of a Python file's bytes, under PEP263_POLICY."""

    verdict: str  # plain, transparent, foreign, unknown, refused, undeterminable
    codec: Optional[str]  # the codec CPython applies (transparent, foreign)
    declared: Optional[str]  # the cookie's name as written
    immune: bool  # the spelling cannot be taken over at run time
    skip_first_line: bool  # only `python -x` reads this cookie

    @property
    def lost(self) -> bool:
        """Semgrep and secrets cannot read this file as its program."""
        return self.verdict in ("foreign", "unknown", "undeterminable")


class UndecodableSource(OSError):
    """A Python file whose program the engine cannot read as CPython runs it."""

    def __init__(self, path, reason: str) -> None:
        super().__init__(errno.EILSEQ, reason, str(path))
        self.reason = reason


def _normal_name(s: str) -> str:
    """Parser/tokenizer/helpers.c get_normal_name."""
    buf = "".join("-" if c == "_" else c.lower() for c in s[:12])
    if buf == "utf-8" or buf.startswith("utf-8-"):
        return "utf-8"
    if buf in ("latin-1", "iso-8859-1", "iso-latin-1") or buf.startswith(("latin-1-", "iso-8859-1-", "iso-latin-1-")):
        return "iso-8859-1"
    return s


def _normalize(s: str) -> str:
    """encodings.normalize_encoding of the lower-cased name (and C's
    _Py_normalize_encoding): runs of characters other than ASCII letters,
    digits and '.' become one '_' between kept characters."""
    out: List[str] = []
    punct = False
    for c in s.lower():
        if (c.isascii() and c.isalnum()) or c == ".":
            if punct and out:
                out.append("_")
            out.append(c)
            punct = False
        else:
            punct = True
    return "".join(out)


def _resolve(spec: str, skip_first_line: bool = False) -> SourceEncoding:
    n = _normal_name(spec)
    if n == "utf-8":
        return SourceEncoding("transparent", "utf-8", spec, True, skip_first_line)
    if n == "iso-8859-1":
        return SourceEncoding("transparent", "iso8859-1", spec, True, skip_first_line)
    norm = _normalize(spec)
    aliased = _PEP263_ALIASES.get(norm) or _PEP263_ALIASES.get(norm.replace(".", "_"))
    for mod in ([aliased] if aliased else []) + [norm]:
        if mod and "." not in mod and mod in _PEP263_MODULES:
            entry = _PEP263_MODULES[mod]
            cls = entry["class"]
            if cls == "refused":
                # Stock CPython refuses a cookie that names a non-text transform codec (hex,
                # base64, zlib, uu, bz2, quopri, rot13, undefined and their aliases) because the
                # registry says it is not a text encoding. The registry is what a module of the
                # scanned repository rewrites, so under D2-A it is foreign, lost like every other
                # cookie that is not a takeover-immune spelling (CL-2, A-2). A byte-order mark
                # beside another codec is refused by the tokenizer, not the registry, and stays
                # refused (python_source_encoding).
                cls = "foreign"
            codec = entry["codec"] if cls in ("transparent", "foreign") else None
            return SourceEncoding(cls, codec, spec, cls == "transparent" and norm in _PEP263_FAST, skip_first_line)
    return SourceEncoding("unknown", None, spec, False, skip_first_line)


def _split_line(data: bytes, start: int) -> Tuple[bytes, int, bool]:
    """The line at `start`, the offset after its terminator, and whether it has
    one (\r\n, \r or \n: universal newlines, as CPython reads source)."""
    n = len(data)
    i = start
    while i < n:
        c = data[i]
        if c == 0x0A:
            return data[start:i], i + 1, True
        if c == 0x0D:
            return data[start:i], (i + 2 if i + 1 < n and data[i + 1] == 0x0A else i + 1), True
        i += 1
    return data[start:], n, False


def _coding_spec(line: bytes, terminated: bool) -> Optional[str]:
    """Parser/tokenizer/helpers.c get_coding_spec: the cookie of a line that is
    nothing but a comment, or None."""
    size = len(line) + (1 if terminated else 0)
    i = 0
    while i < size - 6:
        c = line[i]
        if c == 0x23:
            break
        if c not in (0x20, 0x09, 0x0C):
            return None
        i += 1
    else:
        return None
    for j in range(i, size - 6):
        if line[j:j + 6] != b"coding":
            continue
        t = j + 6
        if t >= len(line) or line[t] not in b":=":
            continue
        t += 1
        while t < len(line) and line[t] in (0x20, 0x09):
            t += 1
        begin = t
        while t < len(line) and (chr(line[t]).isascii() and (chr(line[t]).isalnum() or line[t] in b"-_.")):
            t += 1
        if t > begin:
            return line[begin:t].decode("ascii")
    return None


def _comment_only(line: bytes) -> bool:
    """A line after which CPython still looks for a cookie on the next line."""
    for c in line:
        if c in (0x23, 0x0A, 0x0D):
            return True
        if c not in (0x20, 0x09, 0x0C):
            return False
    return True


def _policy(enc: SourceEncoding) -> SourceEncoding:
    if PEP263_POLICY == "d2a" and enc.verdict == "transparent" and not enc.immune:
        return enc._replace(verdict="foreign")
    return enc


def _plain(skip: bool = False) -> SourceEncoding:
    return SourceEncoding("plain", None, None, False, skip)


def python_source_encoding(data: bytes, complete: bool = True) -> SourceEncoding:
    """What CPython makes of `data`, a Python file's bytes (all of them, or a
    prefix when `complete` is False), on the import path, as a script and under
    `python -x`; the riskiest of those readings wins."""
    undet = SourceEncoding("undeterminable", None, None, False, False)
    # Import and script: an optional UTF-8 BOM, then lines 1 and 2.
    bom = data.startswith(_BOM)
    body = data[3:] if bom else data
    line1, pos, t1 = _split_line(body, 0)
    if not t1 and not complete:
        a = undet
    else:
        spec = _coding_spec(line1, t1)
        if spec is None and _comment_only(line1):
            line2, _, t2 = _split_line(body, pos)
            spec = None if (not t2 and not complete) else _coding_spec(line2, t2)
            if not t2 and not complete:
                spec = ""
        if spec == "":
            a = undet
        elif spec is None:
            a = _plain()
        elif bom and _normal_name(spec) != "utf-8":
            a = SourceEncoding("refused", None, spec, False, False)
        else:
            a = _policy(_resolve(spec))
    # python -x: line 1 skipped through its \n; the next line is read as line 2.
    nl = data.find(b"\n")
    if nl < 0:
        x = _plain(True) if complete else undet
    else:
        line2, _, t2 = _split_line(data, nl + 1)
        if not t2 and not complete:
            x = undet
        else:
            spec = _coding_spec(line2, t2)
            x = _policy(_resolve(spec, True)) if spec is not None else _plain(True)
    return x if _RANK[x.verdict] > _RANK[a.verdict] else a


def read_python_source(path: Path | str) -> str:
    """The text of the Python file at `path` as CPython runs it: plain and
    transparent files are read as their codec (a stray byte replaced, as before);
    a foreign codec is decoded strictly with that codec, as the import path does.
    Raises UndecodableSource (an OSError) when the program cannot be read so: a
    name only a run-time registration could supply, a cookie only `python -x`
    reads, a foreign file that does not decode. Raises OSError when the file
    cannot be read. Never lets a codec error escape."""
    data = read_regular(path)
    enc = python_source_encoding(data)
    if enc.verdict == "unknown":
        raise UndecodableSource(path, f"unreadable: declared source encoding {enc.declared!r} is not a codec this engine knows")
    if enc.verdict == "foreign":
        if enc.skip_first_line:
            raise UndecodableSource(path, f"unreadable: source encoding {enc.declared!r} declared where only python -x reads it")
        try:
            text = data.decode(enc.codec)
        except Exception as exc:  # noqa: BLE001 - any codec failure is lost evaluation, never a crash
            raise UndecodableSource(path, f"unreadable: declared source encoding {enc.declared!r} does not decode ({type(exc).__name__})") from None
    else:
        body = data[3:] if data.startswith(_BOM) else data
        codec = enc.codec if enc.verdict == "transparent" else "utf-8"
        try:
            text = body.decode(codec or "utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = body.decode("utf-8", errors="replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text.replace("\r\n", "\n").replace("\r", "\n")


# ---------------------------------------------------------------------------
# R6-E7a: a unicode escape in identifier position makes a JavaScript or
# TypeScript file lost evaluation (Release Closure Sprint, owner ruling OR-85:
# "mark lost, identifier-position-aware and regex-aware"). The same lexer as
# go/internal/scope/jsescape.go, pinned by the same vectors
# (go/internal/scope/testdata/jsescape_vectors.json, whose ground truth is the
# TypeScript scanner, never this lexer).
#
# The runtime reads an identifier spelled with escapes (\u0065val(x), \u{65}val)
# as eval(x), but every analyzer that matches identifiers lexically misses it,
# so a file whose dangerous call is spelled so reads complete with no finding.
# An escape is in identifier position when it is outside a string literal, the
# text of a template literal (code inside the substitution is code), a regular
# expression literal, a comment (a hashbang line included) and the text of a JSX
# element. The regex-versus-division ambiguity is decided by the token before; the
# cases the previous token cannot decide (after a closing brace that does not
# certainly end a block of statements, after of, yield and await, after ++, -- and !
# where a statement may or may not have ended, an HTML-like comment) are read both ways, and the file is lost when
# either reading finds an escape. A file the lexer cannot decide within its
# budget is lost too. Every doubt resolves to "lost".
# ---------------------------------------------------------------------------

JS_ESCAPE_REASON = "identifier escape"
# The reason the Python engine records for a file it must report lost evaluation (the
# existing `unreadable:` family, as for a foreign source encoding: no new enum).
JS_ESCAPE_UNREADABLE = "unreadable: an identifier spelled with a unicode escape, which the pattern checks do not read as written"


class JSEscape(NamedTuple):
    found: bool  # some reading of the file has an escape in identifier position
    offset: int  # index of the first such escape, or -1
    undecided: bool  # the lexer gave up within its budget

    @property
    def lost(self) -> bool:
        return self.found or self.undecided


_JS_FLAVOURS = {
    # extension: (jsx, tsx, html comments)
    ".js": (True, False, True), ".cjs": (True, False, True), ".es6": (True, False, True), ".jsx": (True, False, True),
    ".mjs": (True, False, False), ".tsx": (True, True, False),
    ".ts": (False, False, False), ".mts": (False, False, False), ".cts": (False, False, False),
}  # fmt: skip
_JS_LT = frozenset("\n\r  ")
_JS_BLANK = frozenset(
    " \t\x0b\x0c ﻿   　" + "".join(chr(c) for c in range(0x2000, 0x200B))
)
_JS_HEX = frozenset("0123456789abcdefABCDEF")
_JS_ASCII_IDENT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_JS_EXPR_WORDS = frozenset(
    {"return", "typeof", "instanceof", "in", "new", "delete", "void", "throw", "case", "do", "else", "extends", "default"}
)
_JS_AMBIGUOUS_WORDS = frozenset({"of", "yield", "await"})
_JS_BS = chr(92)
_JS_MAX_DEPTH = 20000
_JS_BUDGET_PER_CHAR = 64
_JS_BUDGET_FLOOR = 200000
_JS_MAX_STATES = 20000
# the limits a reading gives up at; giving up is never a clean answer, the file is lost
_JS_GIVE_UP_DEPTH, _JS_GIVE_UP_STATES, _JS_GIVE_UP_STEPS, _JS_GIVE_UP_TYPE_ARGS = "depth", "states", "steps", "type arguments"
# how a scan for the end of a JSX element's type arguments can end besides closing (negative: not an offset)
_TA_OPEN, _TA_UNSKIPPABLE = -1, -2
# the previous-token classes
_P_EXPR, _P_VALUE, _P_BRACE, _P_WORD = 0, 1, 2, 3
# what the last piece of a JSX tag was
_TP_START, _TP_NAME, _TP_EQ, _TP_OTHER = 0, 1, 2, 3
# the frame kinds
_F_PAREN, _F_BRACE, _F_TEMPL, _F_JSX_EXPR, _F_JSX_TAG, _F_JSX_ELEM = 0, 1, 2, 3, 4, 5


def js_source(name: str) -> bool:
    """True when `js_identifier_escape` reads a file of this name (a Vue
    single-file component is not one: Semgrep records it lost evaluation already)."""
    dot = name.rfind(".")
    return dot >= 0 and name[dot:].lower() in _JS_FLAVOURS


class _JSFrame:
    __slots__ = ("kind", "ctl", "closing", "blk", "parent", "depth", "hash")

    def __init__(self, kind: int, ctl: bool, closing: bool, parent: "_JSFrame | None", blk: bool = False) -> None:
        self.kind, self.ctl, self.closing, self.parent, self.blk = kind, ctl, closing, parent, blk
        self.depth = 1 if parent is None else parent.depth + 1
        h = kind * 2 + 1 + (7 if ctl else 0) + (13 if closing else 0) + (101 if blk else 0)
        self.hash = ((0 if parent is None else parent.hash) * 1099511628211 + h) & 0xFFFFFFFFFFFFFFFF


class _JSState:
    __slots__ = ("pos", "prev", "dot", "ctl", "for_tok", "line_head", "block_next", "tag_prev", "top")

    def __init__(self) -> None:
        self.pos = 0
        self.prev = _P_EXPR
        self.dot = self.ctl = self.for_tok = False
        self.line_head = True
        # True when a `{` here certainly opens a block of statements: at the start of a file,
        # after `;`, `{` or `}`, after the head of an if, for, while, with, switch or catch,
        # after `=>`, else, do, try and finally.
        self.block_next = True
        # What the last piece of a JSX tag was while a tag is being read: a name, an `=`, or
        # anything else. A `<` right after a name opens type arguments (`<Select<string> />`).
        self.tag_prev = _TP_START
        self.top: "_JSFrame | None" = None

    def copy(self) -> "_JSState":
        c = _JSState()
        c.pos, c.prev, c.dot, c.ctl, c.for_tok, c.line_head, c.block_next, c.tag_prev, c.top = (
            self.pos, self.prev, self.dot, self.ctl, self.for_tok, self.line_head, self.block_next, self.tag_prev, self.top,
        )  # fmt: skip
        return c

    def key(self) -> tuple:
        top = self.top
        return (
            self.pos, self.prev, self.dot, self.ctl, self.for_tok, self.line_head, self.block_next, self.tag_prev,
            -1 if top is None else top.kind, 0 if top is None else top.hash,
        )  # fmt: skip

    def tok(self, prev: int) -> None:
        self.prev = prev
        self.dot = self.ctl = self.for_tok = self.line_head = self.block_next = False
        self.tag_prev = _TP_START


class _JSLexer:
    def __init__(self, src: str, jsx: bool, tsx: bool, html: bool) -> None:
        self.src, self.n = src, len(src)
        self.jsx, self.tsx, self.html = jsx, tsx, html
        self.found = -1
        self.steps = 0
        self.limit = _JS_BUDGET_PER_CHAR * self.n + _JS_BUDGET_FLOOR
        self.work: list[_JSState] = []
        self.seen: set = set()
        self.gave_up = False
        # the first limit the lexer gave up at (one of the _JS_GIVE_UP_* names), "" until it has
        self.why = ""

    # -- the driver --------------------------------------------------------
    def decide(self) -> JSEscape:
        start = _JSState()
        self.work.append(start)
        self.seen.add(start.key())
        while self.work and self.found < 0 and not self.gave_up:
            self._run(self.work.pop())
        return JSEscape(self.found >= 0, self.found, self.found < 0 and self.gave_up)

    def _give_up(self, why: str) -> None:
        """Stop the search: the file is lost evaluation (undecided)."""
        self.gave_up = True
        if not self.why:
            self.why = why

    def _fork(self, st: _JSState) -> None:
        k = st.key()
        if k in self.seen:
            return
        if len(self.seen) >= _JS_MAX_STATES:
            self._give_up(_JS_GIVE_UP_STATES)
            return
        self.seen.add(k)
        self.work.append(st)

    def _run(self, st: _JSState) -> None:
        n = self.n
        while st.pos < n and self.found < 0 and not self.gave_up:
            self.steps += 1
            if self.steps > self.limit:
                self._give_up(_JS_GIVE_UP_STEPS)
                return
            if st.top is not None and st.top.depth > _JS_MAX_DEPTH:
                self._give_up(_JS_GIVE_UP_DEPTH)
                return
            top = st.top
            if top is not None and top.kind == _F_JSX_ELEM:
                self._jsx_children(st)
            elif top is not None and top.kind == _F_JSX_TAG:
                self._jsx_tag(st)
            else:
                self._code(st)

    # -- character classes -------------------------------------------------
    def _escape_len(self, i: int) -> int:
        src, n = self.src, self.n
        if i + 1 >= n or src[i] != _JS_BS or src[i + 1] != "u":
            return 0
        j = i + 2
        if j < n and src[j] == "{":
            k = j + 1
            while k < n and src[k] in _JS_HEX:
                k += 1
            if k > j + 1 and k < n and src[k] == "}":
                return k + 1 - i
            return 0
        if j + 4 <= n and all(src[j + d] in _JS_HEX for d in range(4)):
            return 6
        return 0

    def _ident_len(self, i: int) -> int:
        c = self.src[i]
        if c < "\x80":
            return 1 if c in _JS_ASCII_IDENT else 0
        return 0 if (c in _JS_BLANK or c in _JS_LT) else 1

    def _line_end(self, i: int) -> int:
        src, n = self.src, self.n
        while i < n and src[i] not in _JS_LT:
            i += 1
        return i

    def _word(self, i: int) -> int:
        src, n = self.src, self.n
        while i < n:
            if self._ident_len(i):
                i += 1
                continue
            if src[i] == _JS_BS:
                length = self._escape_len(i)
                if length:
                    if self.found < 0:
                        self.found = i
                    return i + length
            break
        return i

    # -- template text, regex, comments -----------------------------------
    def _template_text(self, st: _JSState) -> None:
        src, n = self.src, self.n
        i = st.pos
        while i < n:
            c = src[i]
            if c == _JS_BS:
                i += 2
                continue
            if c == "`":
                st.pos = i + 1
                st.tok(_P_VALUE)
                return
            if c == "$" and i + 1 < n and src[i + 1] == "{":
                st.pos = i + 2
                st.top = _JSFrame(_F_TEMPL, False, False, st.top)
                st.tok(_P_EXPR)
                return
            i += 1
        st.pos = n

    def _regex(self, i: int) -> int:
        """End of the regular-expression literal that starts at i (a slash), or -1."""
        src, n = self.src, self.n
        j = i + 1
        in_class = False
        while j < n:
            c = src[j]
            if c == _JS_BS:
                j += 1
                if j >= n or src[j] in _JS_LT:
                    return -1
                j += 1
                continue
            if c in _JS_LT:
                return -1
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                return self._word(j + 1)
            j += 1
        return -1

    def _skip_blank(self, st: _JSState) -> bool:
        src, n, i = self.src, self.n, st.pos
        c = src[i]
        if c in _JS_BLANK:
            st.pos += 1
            return True
        if c in _JS_LT:
            st.pos += 2 if (c == "\r" and i + 1 < n and src[i + 1] == "\n") else 1
            st.line_head = True
            return True
        if c == "/" and i + 1 < n:
            d = src[i + 1]
            if d == "/":
                st.pos = self._line_end(i + 2)
                return True
            if d == "*":
                end = src.find("*/", i + 2)
                if end < 0:
                    st.pos = n
                    return True
                if any(ch in _JS_LT for ch in src[i + 2 : end]):
                    st.line_head = True
                st.pos = end + 2
                return True
        return False

    # -- code ---------------------------------------------------------------
    def _code(self, st: _JSState) -> None:
        src, n = self.src, self.n
        i = st.pos
        if i == 0 and n >= 2 and src[0] == "#" and src[1] == "!":
            st.pos = self._line_end(2)
            return
        if self._skip_blank(st):
            return
        c = src[i]
        if c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == _JS_BS:
                    if j + 1 < n:
                        d = src[j + 1]
                        if d == "\r" and j + 2 < n and src[j + 2] == "\n":
                            j += 3
                        elif d in _JS_LT:
                            j += 2
                        else:
                            j += 2
                    else:
                        j += 1
                    continue
                if src[j] == "\n" or src[j] == "\r":
                    break
                j += 1
            if j < n and src[j] == c:
                j += 1
            st.pos = j
            st.tok(_P_VALUE)
        elif c == "`":
            st.pos = i + 1
            st.tok(_P_VALUE)
            self._template_text(st)
        elif ("0" <= c <= "9") or (c == "." and i + 1 < n and "0" <= src[i + 1] <= "9"):
            j = i + 1
            hexa = c == "0" and j < n and src[j] in "xX"
            while j < n:
                d = src[j]
                if (d in _JS_ASCII_IDENT and d != "$") or d == ".":
                    j += 1
                    if not hexa and d in "eE" and j < n and src[j] in "+-":
                        j += 1
                    continue
                break
            st.pos = j
            st.tok(_P_VALUE)
        elif self._ident_len(i) or c == _JS_BS or (c == "#" and i + 1 < n and (self._ident_len(i + 1) or src[i + 1] == _JS_BS)):
            start = i
            if c == "#":
                i += 1
            if c == _JS_BS and self._escape_len(i) == 0:
                st.pos = i + 1  # a stray backslash: a syntax error, not an identifier
                st.tok(_P_EXPR)
                return
            end = self._word(i)
            if self.found >= 0:
                return
            text = src[start:end]
            st.pos = end
            dot, for_tok = st.dot, st.for_tok
            if c == "#" or dot:
                st.tok(_P_VALUE)
            elif text in _JS_EXPR_WORDS:
                st.tok(_P_EXPR)
                st.block_next = text == "else" or text == "do"
            elif text in _JS_AMBIGUOUS_WORDS:
                st.tok(_P_WORD)
                if text == "await" and for_tok:
                    st.ctl = True
            else:
                st.tok(_P_VALUE)
                if text in ("if", "while", "with", "switch", "catch"):
                    st.ctl = True
                elif text == "for":
                    st.ctl = st.for_tok = True
                elif text in ("try", "finally"):
                    st.block_next = True
        elif c == "/":
            self._slash(st)
        elif c == "(":
            st.top = _JSFrame(_F_PAREN, st.ctl, False, st.top)
            st.pos = i + 1
            st.tok(_P_EXPR)
        elif c == ")":
            st.pos = i + 1
            if st.top is not None and st.top.kind == _F_PAREN:
                ctl = st.top.ctl
                st.top = st.top.parent
                st.tok(_P_EXPR if ctl else _P_VALUE)
                st.block_next = ctl
            else:
                st.tok(_P_VALUE)
        elif c == "{":
            st.top = _JSFrame(_F_BRACE, False, False, st.top, st.block_next)
            st.pos = i + 1
            st.tok(_P_EXPR)
            st.block_next = True
        elif c == "}":
            st.pos = i + 1
            top = st.top
            if top is not None and top.kind == _F_BRACE:
                st.top = top.parent
                st.tok(_P_EXPR if top.blk else _P_BRACE)  # a block ends: a statement starts
                st.block_next = True
            elif top is not None and top.kind == _F_TEMPL:
                st.top = top.parent
                self._template_text(st)
            elif top is not None and top.kind == _F_JSX_EXPR:
                st.top = top.parent
                st.tok(_P_VALUE)
            else:
                st.tok(_P_BRACE)
                st.block_next = True
        elif c == "]":
            st.pos = i + 1
            st.tok(_P_VALUE)
        elif c == "!":
            st.pos = i + 1
            if (i + 1 < n and src[i + 1] == "=") or st.prev == _P_EXPR or st.line_head:
                st.tok(_P_EXPR)
            elif st.prev == _P_VALUE:
                st.tok(_P_VALUE)  # TypeScript's postfix non-null assertion
            else:
                alt = st.copy()
                alt.tok(_P_EXPR)
                self._fork(alt)
                st.tok(_P_VALUE)
        elif c in "[,;:@~":
            st.pos = i + 1
            st.tok(_P_EXPR)
            st.block_next = c == ";"
        elif c == ".":
            if i + 2 < n and src[i + 1] == "." and src[i + 2] == ".":
                st.pos = i + 3
                st.tok(_P_EXPR)
            else:
                st.pos = i + 1
                st.tok(_P_EXPR)
                st.dot = True
        elif c == "?":
            if i + 1 < n and src[i + 1] == "." and not (i + 2 < n and "0" <= src[i + 2] <= "9"):
                st.pos = i + 2
                st.tok(_P_EXPR)
                st.dot = True
            else:
                st.pos = i + 1
                st.tok(_P_EXPR)
        elif c == "+" or c == "-":
            if i + 1 < n and src[i + 1] == c:
                if c == "-" and self.html and st.line_head and i + 2 < n and src[i + 2] == ">":
                    alt = st.copy()
                    alt.pos = self._line_end(i + 3)
                    self._fork(alt)
                st.pos = i + 2
                if st.prev == _P_VALUE and not st.line_head:
                    st.tok(_P_VALUE)  # postfix: a value was just read
                elif st.prev == _P_EXPR or st.line_head:
                    st.tok(_P_EXPR)  # prefix: an operand is due (a postfix ++ cannot follow a line break)
                else:  # after `}`, of, yield, await: read it both ways
                    alt = st.copy()
                    alt.tok(_P_EXPR)
                    self._fork(alt)
                    st.tok(_P_VALUE)
                return
            st.pos = i + 1
            st.tok(_P_EXPR)
        elif c == "<":
            self._less(st)
        elif c == "=" and i + 1 < n and src[i + 1] == ">":
            st.pos = i + 2
            st.tok(_P_EXPR)
            st.block_next = True  # an arrow function's body
        else:
            st.pos = i + 1
            st.tok(_P_EXPR)

    def _slash(self, st: _JSState) -> None:
        i, n, src = st.pos, self.n, self.src

        def division(s: _JSState) -> _JSState:
            s.pos = i + 2 if (i + 1 < n and src[i + 1] == "=") else i + 1
            s.tok(_P_EXPR)
            return s

        if st.prev == _P_VALUE:
            division(st)
            return
        end = self._regex(i)
        if self.found >= 0:
            return
        if st.prev == _P_EXPR:
            if end < 0:
                division(st)
            else:
                st.pos = end
                st.tok(_P_VALUE)
        elif end >= 0:  # after a closing brace, of, yield, await: read it both ways
            self._fork(division(st.copy()))
            st.pos = end
            st.tok(_P_VALUE)
        else:
            division(st)

    def _less(self, st: _JSState) -> None:
        src, n, i = self.src, self.n, st.pos

        def op(s: _JSState) -> _JSState:
            j = i + 1
            while j < n and src[j] in "<=" and j < i + 3:
                j += 1
            s.pos = j
            s.tok(_P_EXPR)
            return s

        if self.html and src.startswith("<!--", i):
            alt = st.copy()
            alt.pos = self._line_end(i + 4)
            self._fork(alt)
            op(st)
            return

        def jsx(s: _JSState) -> bool:
            if not self.jsx or i + 1 >= n:
                return False
            d = src[i + 1]
            if not (d == ">" or d == _JS_BS or (self._ident_len(i + 1) and not ("0" <= d <= "9"))):
                return False
            s.top = _JSFrame(_F_JSX_TAG, False, False, s.top)
            s.pos = i + 1
            s.tok(_P_EXPR)
            return True

        if st.prev == _P_VALUE:
            op(st)
        elif st.prev == _P_EXPR:
            alt = op(st.copy())
            if jsx(st):
                # `<` where an expression starts is an element, unless it opens a type parameter
                # list (`<T,>(x) => ...` in TypeScript, `<T>(x) => ...` in Flow): where the text after
                # it could be one, read it both ways.
                if self._type_param_start(i + 1):
                    self._fork(alt)
            else:
                op(st)
        else:
            o = op(st.copy())
            if jsx(st):
                self._fork(o)
            else:
                op(st)

    def _skip_trivia(self, j: int) -> int:
        """The end of the blanks, line breaks and comments that start at j."""
        src, n = self.src, self.n
        while j < n:
            c = src[j]
            if c in _JS_BLANK or c in _JS_LT:
                j += 1
            elif c == "/" and j + 1 < n and src[j + 1] == "/":
                j = self._line_end(j + 2)
            elif c == "/" and j + 1 < n and src[j + 1] == "*":
                end = src.find("*/", j + 2)
                if end < 0:
                    return n
                j = end + 2
            else:
                break
        return j

    def _name_end(self, j: int) -> int:
        """The end of the identifier (escapes included) that starts at j, or j."""
        n = self.n
        while j < n:
            if self._ident_len(j):
                j += 1
            else:
                length = self._escape_len(j)
                if not length:
                    break
                j += length
        return j

    def _type_param_start(self, i: int) -> bool:
        """Whether the text after a `<` (at i - 1) could start a type parameter list: variance or
        modifiers (`+`, `-`, `const`, `in`, `out`), a name, and then `,`, `=`, `:`, `extends`, or a `>`
        followed by `(`. Wide on purpose: it only decides where a `<` is read both ways."""
        src, n = self.src, self.n
        j = self._skip_trivia(i)
        for _ in range(4):
            if j >= n:
                return False
            if src[j] in "+-":
                j = self._skip_trivia(j + 1)
            e = self._name_end(j)
            if e == j:
                return False
            if src[j:e] in ("const", "in", "out"):
                nj = self._skip_trivia(e)
                if nj > e and nj < n and (self._ident_len(nj) or src[nj] == _JS_BS):
                    j = nj
                    continue
            e = self._skip_trivia(e)
            if e >= n:
                return False
            if src[e] in ",=:":
                return True
            if src[e] == ">":
                p = self._skip_trivia(e + 1)
                return p < n and src[p] == "("
            return src.startswith("extends", e) and (e + 7 >= n or src[e + 7] not in _JS_ASCII_IDENT)
        # Four modifiers in a row: no type parameter has so many, so this is neither a list nor an
        # element the lexer can name; it reads the `<` both ways, as it reads every doubt.
        return j < n

    def _type_args_end(self, i: int) -> int:
        """The end of the type argument list that starts at i (a `<`, after the name of a JSX element).
        `<Select<string> />`, `<Select<Array<string>> />` and `<Select<(a: number) => void> />` are such
        lists; a `>` that is half of `=>`, a string, a template and a comment are not counted.

        The list has no length limit of its own (a union of 40,000 members is valid): what it costs is
        charged to the step budget (R3-SEC-A2: a 64 KiB limit made the lexer read the rest of the file as
        the text of an element). It ends one of three ways. It closes: the offset after the `>`. Nothing
        closes it before the end of the file, or a comment in it never ends: `_TA_OPEN`; no valid file has
        such a list, so the reading that holds it is not one, and, like an unterminated comment, it ends
        the reading with nothing after it that could be code (in a file where it is a doubt, the other
        reading of the `<` is read too). Or a template in it holds a substitution: `_TA_UNSKIPPABLE`,
        types of their own with templates and angle brackets, which this scan does not read; the caller
        gives up, and giving up is lost evaluation."""
        src, n = self.src, self.n
        depth = 0
        j = i
        while j < n:
            c = src[j]
            if c == "<":
                depth += 1
            elif c == ">":
                if not (j > i and src[j - 1] == "="):
                    depth -= 1
                    if depth == 0:
                        self.steps += j - i
                        return j + 1
            elif c == '"' or c == "'":
                # a string ends at its quote or at a line break (U+2028 and U+2029 may be in it, as in code)
                j += 1
                while j < n and src[j] != c and src[j] != "\n" and src[j] != "\r":
                    if src[j] == _JS_BS:
                        j += 1
                        if j < n and src[j] == "\r" and j + 1 < n and src[j + 1] == "\n":
                            j += 1  # a line continuation: CRLF is one terminator
                    j += 1
            elif c == "`":
                j += 1
                while j < n and src[j] != "`":
                    if src[j] == _JS_BS:
                        j += 1
                    elif src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                        self.steps += j - i
                        return _TA_UNSKIPPABLE
                    j += 1
            elif c == "/" and j + 1 < n and src[j + 1] == "/":
                j = self._line_end(j + 2) - 1
            elif c == "/" and j + 1 < n and src[j + 1] == "*":
                end = src.find("*/", j + 2)
                if end < 0:
                    self.steps += n - i
                    return _TA_OPEN
                j = end + 1
            j += 1
        self.steps += n - i
        return _TA_OPEN

    # -- JSX ---------------------------------------------------------------
    def _jsx_after_element(self, st: _JSState) -> None:
        if st.top is not None and st.top.kind == _F_JSX_ELEM:
            return
        st.tok(_P_VALUE)

    def _jsx_children(self, st: _JSState) -> None:
        src, n = self.src, self.n
        i = st.pos
        while i < n and src[i] != "{" and src[i] != "<":
            i += 1
        st.pos = i
        if i >= n:
            return
        if src[i] == "{":
            st.top = _JSFrame(_F_JSX_EXPR, False, False, st.top)
            st.pos = i + 1
            st.tok(_P_EXPR)
            return
        if i + 1 < n and src[i + 1] == "/":
            st.top = _JSFrame(_F_JSX_TAG, False, True, st.top)
            st.pos = i + 2
            st.tag_prev = _TP_START
            return
        if i + 1 < n and src[i + 1] == "!":
            st.pos = i + 2  # `<!--` is not an element: the TypeScript scanner reads it as text
            return
        st.top = _JSFrame(_F_JSX_TAG, False, False, st.top)
        st.pos = i + 1
        st.tag_prev = _TP_START

    def _jsx_tag(self, st: _JSState) -> None:
        src, n = self.src, self.n
        i = st.pos
        c = src[i]
        if c in _JS_BLANK:
            st.pos += 1
            return
        if c in _JS_LT:
            st.pos += 2 if (c == "\r" and i + 1 < n and src[i + 1] == "\n") else 1
            return
        if c == ">":
            closing = st.top.closing
            st.top = st.top.parent
            st.pos = i + 1
            if closing:
                if st.top is not None and st.top.kind == _F_JSX_ELEM:
                    st.top = st.top.parent
                self._jsx_after_element(st)
            else:
                st.top = _JSFrame(_F_JSX_ELEM, False, False, st.top)
        elif c == "/" and i + 1 < n and src[i + 1] == ">":
            st.top = st.top.parent
            st.pos = i + 2
            self._jsx_after_element(st)
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            st.pos = self._line_end(i + 2)
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            st.pos = n if end < 0 else end + 2
        elif c == "{":
            st.top = _JSFrame(_F_JSX_EXPR, False, False, st.top)
            st.pos = i + 1
            st.tok(_P_EXPR)
        elif c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                j += 1
            st.pos = j + 1 if j < n else j
            st.tag_prev = _TP_OTHER
        elif c == "<":
            if st.tag_prev == _TP_NAME:
                # Right after a tag's name: the type arguments of a generic element, which hold no
                # element and no code (TypeScript, `<Select<string> />`).
                end = self._type_args_end(i)
                if end == _TA_UNSKIPPABLE:
                    # What follows the list could be code, and this scan cannot say where the list ends:
                    # give up (lost evaluation) rather than read on from a guess.
                    self._give_up(_JS_GIVE_UP_TYPE_ARGS)
                    return
                if end == _TA_OPEN:
                    st.pos = self.n  # the list has no end: this reading ends (see _type_args_end)
                    return
                st.pos = end
                st.tag_prev = _TP_OTHER
                return
            st.top = _JSFrame(_F_JSX_TAG, False, False, st.top)
            st.pos = i + 1
            st.tag_prev = _TP_START
        elif c == _JS_BS:
            if self._escape_len(i):
                if self.found < 0:
                    self.found = i
                return
            st.pos = i + 1
            st.tag_prev = _TP_OTHER
        elif c == "=":
            st.pos = i + 1
            st.tag_prev = _TP_EQ
        else:
            st.tag_prev = _TP_NAME if (self._ident_len(i) or c in ".-:") else _TP_OTHER
            st.pos = i + 1


def js_identifier_escape(source: "str | bytes", name: str) -> JSEscape:
    """Whether `source`, the text of the JavaScript or TypeScript file called
    `name`, spells an identifier with a unicode escape (see the section comment).
    A name that is not such a file reads as not found."""
    if isinstance(source, (bytes, bytearray)):
        source = bytes(source).decode("utf-8", errors="replace")
    dot = name.rfind(".")
    flavour = _JS_FLAVOURS.get(name[dot:].lower()) if dot >= 0 else None
    if flavour is None or (_JS_BS + "u") not in source:
        return JSEscape(False, -1, False)
    return _JSLexer(source, *flavour).decide()
