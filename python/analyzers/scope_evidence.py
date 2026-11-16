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

# The codec policy (OWNER-DECISIONS D2, approved). Set "d2a" when the owner
# rules D2-A: only takeover-immune spellings stay UTF-8-equivalent.
PEP263_POLICY = "d2"

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

