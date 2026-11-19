#!/usr/bin/env python3
"""Generator of testdata/javaescape_vectors.json (R6-E7b, Release Closure Sprint, WS-C2).

Ground truth is a real JDK, not this repository's scanner: every vector is a
complete Java file that is compiled and run with `javac` and `java`, and the
program prints HIDDEN-RAN-<tag> when, and only when, its hidden statement
executes. JLS 3.3 translates unicode escapes before the program is lexed, so
`// <escape for LF> System.out.println(...)` is a comment followed by a statement,
and a lexical analyzer that does not translate sees only the comment.

`expect` is the rule the scanner implements (owner ruling OR-85, R6-E7b option
(4)): a file is lost evaluation when it holds, anywhere, a unicode escape (one
or more u, four hex digits in either case, the backslash preceded by an even
number of backslashes) that translates to a line terminator (LF, CR), a quote
(" or '), a backslash, a slash or an asterisk. `jdk_hidden_ran` is what the JDK
did. A vector whose hidden statement ran must expect a loss; the rule also
reports some files whose hidden statement does not run (an escape inside a
comment, a file that does not compile), never fewer.

Run (needs docker and an official JDK image; the engine images have none):

    python3 gen_javaescape_vectors.py <output dir> [jdk image, default eclipse-temurin:21-jdk]

Never edit the output by hand.
"""

import json
import os
import subprocess
import sys
import tempfile

BS = chr(92)


def esc(hexs: str, us: int = 1) -> str:
    return BS + "u" * us + hexs


def case(cid, note, body, expect, hidden=None, before="", after=""):
    return {"id": cid, "note": note, "body": body, "expect": expect, "before": before, "after": after, "hidden": hidden}


H = "HIDDEN-RAN-"
CASES = [
    case("lf", "an escape for LF ends a // comment: the statement after it runs (the shape of records r6e7 java-u000a)",
         ["// " + esc("000a") + ' System.out.println("' + H + 'LF");'], True, H + "LF"),
    case("lf-upper", "hex digits in upper case", ["// " + esc("000A") + ' System.out.println("' + H + 'LFU");'], True, H + "LFU"),
    case("cr", "an escape for CR ends a // comment", ["// " + esc("000d") + ' System.out.println("' + H + 'CR");'], True, H + "CR"),
    case("cr-upper", "an escape for CR, upper case", ["// " + esc("000D") + ' System.out.println("' + H + 'CRU");'], True, H + "CRU"),
    case("dquote", "an escape for a double quote ends a string literal",
         ['String s = "a' + esc("0022") + '; System.out.println("' + H + 'DQ"); String t = "b";'], True, H + "DQ"),
    case("squote", "an escape for a single quote ends a char literal",
         ["char c = 'a" + esc("0027") + '; System.out.println("' + H + 'SQ"); char d = ' + "'b';"], True, H + "SQ"),
    case("multi-u-2", "two u letters (JLS 3.3: one or more)", ["// " + esc("000a", 2) + ' System.out.println("' + H + 'UU");'], True, H + "UU"),
    case("multi-u-5", "five u letters", ["// " + esc("000a", 5) + ' System.out.println("' + H + 'UUUUU");'], True, H + "UUUUU"),
    case("three-backslashes", "the third backslash is preceded by an even number, so it starts an escape",
         ["// " + BS + BS + esc("000a") + ' System.out.println("' + H + '3BS");'], True, H + "3BS"),
    case("five-backslashes", "the fifth backslash is preceded by four",
         ["// " + BS * 4 + esc("000a") + ' System.out.println("' + H + '5BS");'], True, H + "5BS"),
    case("backslash", "an escape for a backslash escapes the next quote: the string is '\"" + H + "BS'",
         ['String a = "' + esc("005c") + '"" + "' + H + 'BS"; System.out.println(a);'], True, '"' + H + "BS"),
    case("slash-ends-comment", "a block comment ended by * and an escape for a slash",
         ["/* x *" + esc("002f") + ' System.out.println("' + H + 'SLASH"); /* y */'], True, H + "SLASH"),
    case("star-ends-comment", "a block comment ended by an escape for an asterisk and a slash",
         ["/* x " + esc("002a") + '/ System.out.println("' + H + 'STAR"); /* y */'], True, H + "STAR"),
    case("slash-slash-comment", "two escapes for slashes make a comment: nothing hidden runs, the rule still reports the file",
         [esc("002f") + esc("002f") + ' System.out.println("SHOULD-NOT-RUN");'], True),
    case("escaped-backslash-then-u", "an escape for a backslash takes no part in a further escape: nothing hidden runs, the rule still reports the file",
         ["// " + esc("005c") + 'u000a System.out.println("SHOULD-NOT-RUN");'], True),
    case("in-block-comment", "a structural escape inside a block comment: harmless, still reported",
         ["/* " + esc("000a") + " */"], True),
    case("in-line-comment-end", "a structural escape at the end of a line comment",
         ["// text " + esc("000a")], True),
    case("in-javadoc", "a structural escape in a doc comment", ["/** " + esc("002a") + "/"], True),
    case("in-string", "an escape for LF inside a string literal: the string does not end, the file does not compile",
         ['String s = "a' + esc("000a") + 'b";'], True),
    case("in-char", "an escape for LF as a char literal: does not compile", ["char c = '" + esc("000a") + "';"], True),
    case("at-eof", "a structural escape as the last bytes of the file", ["int x = 1;"], True, None, "", "// " + esc("000a")),
    case("in-class-comment", "a structural escape in a comment before the class", ["int x = 1;"], True, None, "// " + esc("000a") + "\n", ""),
    case("even-backslashes", "an even number of backslashes before u is NOT an escape",
         ["// " + BS + BS + 'u000a System.out.println("SHOULD-NOT-RUN");'], False),
    case("four-backslashes", "four backslashes: none eligible",
         ["// " + BS * 4 + 'u000a System.out.println("SHOULD-NOT-RUN");'], False),
    case("nonstructural-string", "an escape for a letter inside a string", ['System.out.println("' + esc("0041") + '");'], False),
    case("nonstructural-ident", "an escape inside an identifier (not a structural character)",
         ["int x = 7; System.out.println(" + esc("0078") + ");"], False),
    case("nonstructural-space", "an escape for a space", ["int" + esc("0020") + "x = 1;"], False),
    case("nonstructural-tab-and-ff", "escapes for a tab and a form feed", ["int" + esc("0009") + "x" + esc("000c") + "= 1;"], False),
    case("nonstructural-brace-paren", "escapes for punctuation that is not structural here",
         ["System.out.println" + esc("0028") + '"x"' + esc("0029") + esc("003b")], False),
    case("upper-case-U", "a capital U is not an escape", ["// " + BS + 'U000a x'], False),
    case("illegal-escape", "an escape with a non-hex digit is a compile error and translates to nothing", ["// " + BS + "u00zz"], False),
    case("truncated-escape", "an escape cut short at the end of the file", ["int x = 1;"], False, None, "", "// " + BS + "u00"),
    case("backslash-u-no-digits", "a backslash and u with no digits", ["// " + BS + "u "], False),
    case("backslash-letter", "a backslash before another letter", ["// " + BS + "n " + BS + "t"], False),
    case("plain", "a file with no backslash", ['System.out.println("plain");'], False),
    case("string-escapes", "ordinary string escapes", ['System.out.println("a' + BS + "n" + BS + 't' + BS + '"' + BS + BS + '");'], False),
]


def render(c):
    cls = "H_" + c["id"].replace("-", "_")
    body = "\n        ".join(c["body"])
    src = "public class " + cls + " {\n    public static void main(String[] args) {\n        " + body + '\n        System.out.println("DONE");\n    }\n}\n'
    return cls, c["before"] + src + c["after"]


def main():
    out = sys.argv[1]
    image = sys.argv[2] if len(sys.argv) > 2 else "eclipse-temurin:21-jdk"
    work = tempfile.mkdtemp(prefix="javaesc-")
    rows = []
    for c in CASES:
        cls, src = render(c)
        os.makedirs(os.path.join(work, c["id"]), exist_ok=True)
        with open(os.path.join(work, c["id"], cls + ".java"), "w", encoding="utf-8", newline="") as fh:
            fh.write(src)
        rows.append((c, cls, src))
    script = (
        "for d in /src/*; do id=$(basename $d); cls=$(ls $d | sed 's/.java$//'); echo \"@@@ $id\"; mkdir -p /tmp/o/$id; "
        "if javac -d /tmp/o/$id $d/$cls.java > /tmp/o/$id.javac 2>&1; then echo \"compiled=1\"; java -cp /tmp/o/$id $cls 2>&1; else echo \"compiled=0\"; fi; done"
    )
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", work + ":/src:ro", "--entrypoint", "sh", image, "-c", script + "; java -version 2>&1 | head -1"],
                       capture_output=True, text=True, timeout=900)
    sections, cur = {}, None
    version = ""
    for line in r.stdout.splitlines():
        if line.startswith("@@@ "):
            cur = line[4:]
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    if sections:
        last = sections[cur]
        if last and last[-1].startswith("openjdk "):
            version = last.pop()
    vectors = []
    for c, cls, src in rows:
        lines = sections[c["id"]]
        compiled = "compiled=1" in lines
        printed = [l for l in lines if not l.startswith("compiled=")]
        hidden = any(H in l for l in printed)
        if c["hidden"] is not None and compiled and c["hidden"] not in printed:
            raise SystemExit(f"{c['id']}: the JDK did not print {c['hidden']} (got {printed})")
        if c["hidden"] is None and hidden:
            raise SystemExit(f"{c['id']}: the JDK ran a hidden statement this vector does not declare")
        if hidden and not c["expect"]:
            raise SystemExit(f"{c['id']}: a hidden statement ran and the vector expects it clean")
        vectors.append({"id": c["id"], "note": c["note"], "text": src, "expect": c["expect"], "jdk_compiled": compiled, "jdk_output": printed, "jdk_hidden_ran": hidden})
    doc = {
        "schema": 1,
        "about": "Vectors for scope.JavaStructuralEscape (R6-E7b). Generated by gen_javaescape_vectors.py against a real JDK; never edited by hand.",
        "jdk": {"image": image, "version": version},
        "rule": "a unicode escape (JLS 3.3) that translates to LF, CR, a double quote, a single quote, a backslash, a slash or an asterisk, anywhere in the file",
        "vectors": vectors,
    }
    with open(os.path.join(out, "javaescape_vectors.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print(f"wrote {len(vectors)} vectors; hidden statement ran in {sum(v['jdk_hidden_ran'] for v in vectors)}; jdk {version}")


if __name__ == "__main__":
    main()
