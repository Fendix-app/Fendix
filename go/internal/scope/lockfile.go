package scope

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Lockfiles (decision D5-2, contract C6). A file is a lockfile only when BOTH
// hold:
//
//   - its exact base name is one of the closed list below, and
//   - its WHOLE content parses as that name's format. A recognizer reads to the
//     end of the file, accepts only the format's own structure (the known keys,
//     sections and line shapes, with their values limited to the characters
//     package names, versions, URLs and hashes are written in), and rejects the
//     file at the first line or token that is anything else.
//
// A file with one of these names that is a lockfile in its first lines and
// source code, or a secret in an unknown key, after them is therefore not a
// lockfile and is in scope. A head-only check (round 4) could be satisfied by a
// forged first line.
//
// The list is closed and documented here; adding a name needs a recognizer:
//
//	package-lock.json, npm-shrinkwrap.json   npm, lockfileVersion 1-3
//	yarn.lock                                 Yarn classic (v1) and Berry
//	pnpm-lock.yaml                            pnpm
//	poetry.lock                               Poetry
//	Pipfile.lock                              Pipenv
//	Cargo.lock                                Cargo
//	go.sum                                    Go modules
//	composer.lock                             Composer
//	Gemfile.lock                              Bundler
//
// What a recognizer cannot do is judge the identifiers it accepts: a package
// name, a version string and a URL are free text within their character set, so
// a secret written as a package name in an otherwise well-formed lockfile is
// still skipped. That is the trust the exclusion carries; it is listed by name
// in the scan's declared-out-of-scope detail and complete in the report's
// metadata, so it is never silent.

// maxLockfileBytes bounds how much of a file a recognizer reads. A larger file
// is not a lockfile (it is read like any other file, or recorded as over the
// cap).
const maxLockfileBytes = 32 << 20

// lockfileCheck decides whether the whole content read from r is the format.
type lockfileCheck func(r io.Reader) bool

// lockfiles maps each lockfile name to its recognizer.
var lockfiles = map[string]lockfileCheck{
	"package-lock.json":   checkJSON(npmLockSchema, "lockfileVersion"),
	"npm-shrinkwrap.json": checkJSON(npmLockSchema, "lockfileVersion"),
	"Pipfile.lock":        checkJSON(pipfileLockSchema, "_meta", "default"),
	"composer.lock":       checkJSON(composerLockSchema, "content-hash", "packages"),
	"yarn.lock":           checkYarn,
	"pnpm-lock.yaml":      checkPnpm,
	"poetry.lock":         checkTOML(rePoetryHeader),
	"Cargo.lock":          checkTOML(reCargoHeader),
	"go.sum":              checkGoSum,
	"Gemfile.lock":        checkGemfileLock,
}

// ---------------------------------------------------------------------------
// Line reading shared by the text formats.

// scanLines calls fn with every line of r (a trailing CR removed). It fails
// when a line is longer than 64 KiB, holds a NUL, a control character other
// than a tab, or invalid UTF-8, or when fn rejects it. The file must have at
// least one line.
func scanLines(r io.Reader, fn func(n int, line string) bool) bool {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	n := 0
	for sc.Scan() {
		n++
		b := sc.Bytes()
		if len(b) > 0 && b[len(b)-1] == '\r' {
			b = b[:len(b)-1]
		}
		if !utf8.Valid(b) {
			return false
		}
		for _, c := range b {
			if c < 0x20 && c != '\t' || c == 0x7f {
				return false
			}
		}
		if !fn(n, string(b)) {
			return false
		}
	}
	return sc.Err() == nil && n > 0
}

// ---------------------------------------------------------------------------
// go.sum

var reGoSumLine = regexp.MustCompile(`^([A-Za-z0-9._~+\-/!]+) (v[0-9][0-9A-Za-z.+\-]*)(/go\.mod)? h1:[A-Za-z0-9+/]{43}=$`)

func checkGoSum(r io.Reader) bool {
	lines := 0
	ok := scanLines(r, func(_ int, line string) bool {
		m := reGoSumLine.FindStringSubmatch(line)
		if m == nil {
			return false
		}
		// A module path's first element is a host name (go.sum records
		// downloaded modules), so it holds a dot.
		first, _, _ := strings.Cut(m[1], "/")
		if !strings.Contains(first, ".") {
			return false
		}
		lines++
		return true
	})
	return ok && lines > 0
}

// ---------------------------------------------------------------------------
// Gemfile.lock

var (
	reGemSection  = regexp.MustCompile(`^(GEM|GIT|PATH|PLUGIN SOURCE|PLATFORMS|DEPENDENCIES|BUNDLED WITH|RUBY VERSION|CHECKSUMS|SPECS)$`)
	reGemKV       = regexp.MustCompile(`^  (remote|revision|branch|tag|ref|glob|submodules|name|version): [A-Za-z0-9._~:/?#@!$&'()*+,;=%\- ]{1,500}$`)
	reGemSpecs    = regexp.MustCompile(`^  specs:$`)
	reGemSpec     = regexp.MustCompile(`^    [A-Za-z0-9._\-]+ \([A-Za-z0-9._\-]+\)$`)
	reGemSpecDep  = regexp.MustCompile(`^      [A-Za-z0-9._\-]+(?: \([A-Za-z0-9._<>=~!, \-]+\))?$`)
	reGemPlatform = regexp.MustCompile(`^  [A-Za-z0-9._\-]+$`)
	reGemDep      = regexp.MustCompile(`^  [A-Za-z0-9._\-]+!?(?: \([A-Za-z0-9._<>=~!, \-]+\))?!?$`)
	reGemBundled  = regexp.MustCompile(`^   [0-9][0-9A-Za-z.\-]*$`)
	reGemRuby     = regexp.MustCompile(`^   ruby [0-9][0-9A-Za-z.\-]*(?:p[0-9]+)?$`)
	reGemSum      = regexp.MustCompile(`^  [A-Za-z0-9._\-]+ \([A-Za-z0-9._\-]+\) sha256=[0-9a-f]{64}$`)
)

func checkGemfileLock(r io.Reader) bool {
	section := ""
	sections := 0
	ok := scanLines(r, func(_ int, line string) bool {
		switch {
		case line == "":
			return true
		case reGemSection.MatchString(line):
			section = line
			sections++
			return true
		}
		switch section {
		case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
			return reGemKV.MatchString(line) || reGemSpecs.MatchString(line) || reGemSpec.MatchString(line) || reGemSpecDep.MatchString(line)
		case "PLATFORMS":
			return reGemPlatform.MatchString(line)
		case "DEPENDENCIES":
			return reGemDep.MatchString(line)
		case "BUNDLED WITH":
			return reGemBundled.MatchString(line)
		case "RUBY VERSION":
			return reGemRuby.MatchString(line)
		case "CHECKSUMS":
			return reGemSum.MatchString(line)
		}
		return false
	})
	return ok && sections > 0
}

// ---------------------------------------------------------------------------
// yarn.lock (classic v1 and Berry) and pnpm-lock.yaml

var (
	// A scalar value in a YAML-shaped lockfile: package names, versions, URLs,
	// hashes and flow lists of them. No backslash, backtick, semicolon or
	// brace-free code character can appear.
	yamlScalar = `(?:"[A-Za-z0-9@/._~+\-^<>=*|:#%!?&,' ()\[\]{}]{0,1000}"|'[A-Za-z0-9@/._~+\-^<>=*|:#%!?&," ()\[\]{}]{0,1000}'|[A-Za-z0-9@/._~+\-^<>=*|#%!?&,()\[\]{}:'" ]{1,1000})`
	yamlKey    = `(?:"[A-Za-z0-9@/._~+\-^<>=*|:#%!?&,' ()]{1,1000}"|'[A-Za-z0-9@/._~+\-^<>=*|:#%!?&," ()]{1,1000}'|[A-Za-z0-9@/._~+\-^<>=*|#%!?&()]{1,1000})`
	reYamlLine = regexp.MustCompile(`^( *)(?:(- )(` + yamlScalar + `)|(` + yamlKey + `):(?: (` + yamlScalar + `))?)$`)
)

// checkYAMLLines accepts the file when every line is blank, an allowed comment,
// or a "key:", "key: scalar" or "- scalar" line indented by whole levels of two
// spaces, and every top-level key is accepted by top.
func checkYAMLLines(r io.Reader, comments []*regexp.Regexp, top func(key string) bool) bool {
	prev := 0
	keys := 0
	ok := scanLines(r, func(_ int, line string) bool {
		if strings.TrimSpace(line) == "" {
			return line == ""
		}
		if line[0] == '#' {
			for _, c := range comments {
				if c.MatchString(line) {
					return true
				}
			}
			return false
		}
		m := reYamlLine.FindStringSubmatch(line)
		if m == nil {
			return false
		}
		indent := len(m[1])
		if indent%2 != 0 || indent > prev+2 {
			return false
		}
		prev = indent
		if m[4] != "" {
			keys++
			if indent == 0 && !top(strings.Trim(m[4], `"'`)) {
				return false
			}
		}
		return true
	})
	return ok && keys > 0
}

var reYarnBerry = regexp.MustCompile(`(?m)^__metadata:\r?$`)

var (
	reYarnComments = []*regexp.Regexp{
		regexp.MustCompile(`^# THIS IS AN AUTOGENERATED FILE\. DO NOT EDIT THIS FILE DIRECTLY\.$`),
		regexp.MustCompile(`^# yarn lockfile v1$`),
		regexp.MustCompile(`^# This file is generated by running "yarn install" inside your project\.$`),
		regexp.MustCompile(`^# Manual changes might be lost - proceed with caution!$`),
	}
	reYarnV1Key   = regexp.MustCompile(`^(?:"[A-Za-z0-9@/._~+\-^<>=*|:#%!?&, ]+"|[A-Za-z0-9@/._~+\-^<>=*|#%]+)(?:, (?:"[A-Za-z0-9@/._~+\-^<>=*|:#%!?&, ]+"|[A-Za-z0-9@/._~+\-^<>=*|#%]+))*:$`)
	reYarnV1Field = regexp.MustCompile(`^  (?:version|resolved|uid|integrity|resolution) "?[A-Za-z0-9@/._~+\-^<>=*|:#%!?&,=$()\[\] ]{1,1000}"?$`)
	reYarnV1Block = regexp.MustCompile(`^  (?:dependencies|optionalDependencies):$`)
	reYarnV1Dep   = regexp.MustCompile(`^    (?:"@?[A-Za-z0-9._~\-/]+"|@?[A-Za-z0-9._~\-/]+) "[A-Za-z0-9@/._~+\-^<>=*|:#%!?&,=$()\[\] ]{1,1000}"$`)
)

func checkYarn(r io.Reader) bool {
	// Berry (yarn 2+) is YAML with a __metadata block; classic is its own
	// format. The first non-blank, non-comment line says which.
	br := bufio.NewReaderSize(r, 64*1024)
	head, _ := br.Peek(64 * 1024)
	berry := reYarnBerry.Match(head)
	var whole io.Reader = br
	if berry {
		seenMeta := false
		return checkYAMLLines(whole, reYarnComments, func(key string) bool {
			if key == "__metadata" {
				seenMeta = true
			}
			return true
		}) && seenMeta
	}
	entries := 0
	inDeps := false
	return scanLines(whole, func(_ int, line string) bool {
		switch {
		case line == "":
			inDeps = false
			return true
		case line[0] == '#':
			for _, c := range reYarnComments {
				if c.MatchString(line) {
					return true
				}
			}
			return false
		case line[0] != ' ':
			inDeps = false
			if !reYarnV1Key.MatchString(line) {
				return false
			}
			entries++
			return true
		case reYarnV1Block.MatchString(line):
			inDeps = true
			return true
		case reYarnV1Field.MatchString(line):
			inDeps = false
			return true
		}
		return inDeps && reYarnV1Dep.MatchString(line)
	}) && entries > 0
}

var pnpmTop = map[string]bool{
	"lockfileVersion": true, "settings": true, "importers": true, "packages": true,
	"snapshots": true, "dependencies": true, "devDependencies": true, "optionalDependencies": true,
	"specifiers": true, "overrides": true, "patchedDependencies": true, "catalogs": true,
	"time": true, "neverBuiltDependencies": true, "onlyBuiltDependencies": true,
	"packageExtensionsChecksum": true, "pnpmfileChecksum": true, "ignoredOptionalDependencies": true,
	"injectedDependencies": true, "dependenciesMeta": true,
}

func checkPnpm(r io.Reader) bool {
	seen := false
	return checkYAMLLines(r, nil, func(key string) bool {
		if !pnpmTop[key] {
			return false
		}
		if key == "lockfileVersion" {
			seen = true
		}
		return true
	}) && seen
}

// ---------------------------------------------------------------------------
// poetry.lock and Cargo.lock (TOML)

var (
	rePoetryHeader = regexp.MustCompile(`^# This file is automatically @generated by Poetry [0-9][0-9A-Za-z.+\-]* and should not be changed by hand\.$`)
	reCargoHeader  = regexp.MustCompile(`^# (?:This file is automatically @generated by Cargo\.|It is not intended for manual editing\.)$`)

	tomlTable = regexp.MustCompile(`^\[\[?(?:package|metadata|patch|root)(?:\.[A-Za-z0-9_\-"]+)*\]\]?$`)
	// A basic string (with \" and \\ escapes), a literal string, a number or
	// boolean, or an array or inline table of those written on one line.
	tomlStr   = `"(?:[^"\\\x00-\x1f]|\\["\\])*"`
	tomlLit   = `'[^'\x00-\x1f]*'`
	tomlAtom  = `(?:` + tomlStr + `|` + tomlLit + `|[0-9][0-9._eE+\-]*|true|false)`
	tomlInner = `(?:` + tomlStr + `|` + tomlLit + `|[A-Za-z0-9_\-.=,<>!~^*|:/@#%()\[\] +{}])*`
	tomlVal   = `(?:` + tomlAtom + `|\[` + tomlInner + `\]|\{` + tomlInner + `\})`
	tomlKV    = regexp.MustCompile(`^([A-Za-z0-9_\-]+|"[A-Za-z0-9_.\-+/ ]+") = (` + tomlVal + `|\[)$`)
	tomlElem  = regexp.MustCompile(`^ *(?:` + tomlStr + `|\{` + tomlInner + `\}),?$`)
)

func checkTOML(header *regexp.Regexp) lockfileCheck {
	return func(r io.Reader) bool {
		inArray := false
		packages := 0
		ok := scanLines(r, func(_ int, line string) bool {
			switch {
			case inArray:
				if strings.TrimSpace(line) == "]" {
					inArray = false
					return true
				}
				return tomlElem.MatchString(line)
			case line == "":
				return true
			case line[0] == '#':
				return header.MatchString(line)
			case line[0] == '[' && line != "[":
				if line == "[[package]]" {
					packages++
				}
				return tomlTable.MatchString(line)
			}
			m := tomlKV.FindStringSubmatch(line)
			if m == nil {
				return false
			}
			if m[2] == "[" {
				inArray = true
			}
			return true
		})
		return ok && !inArray && packages > 0
	}
}

// ---------------------------------------------------------------------------
// JSON lockfiles: a streaming recognizer against a schema of the format's keys.

// jn is a schema node: which JSON values it accepts.
type jn struct {
	str   *regexp.Regexp // a string matching it
	num   bool
	flag  bool
	obj   map[string]*jn // an object with exactly these known keys
	keyRe *regexp.Regexp // an object whose keys match keyRe...
	val   *jn            // ...and whose values are val
	arr   *jn            // an array of
}

// or merges two schema nodes of different kinds: a value accepted by either.
func (a *jn) or(b *jn) *jn {
	out := *a
	if b.str != nil {
		out.str = b.str
	}
	out.num = out.num || b.num
	out.flag = out.flag || b.flag
	if b.obj != nil {
		out.obj = b.obj
	}
	if b.keyRe != nil {
		out.keyRe, out.val = b.keyRe, b.val
	}
	if b.arr != nil {
		out.arr = b.arr
	}
	return &out
}

const maxJSONDepth = 16

type jsonCheck struct {
	dec   *json.Decoder
	count int
}

func (c *jsonCheck) value(n *jn, depth int) bool {
	if depth > maxJSONDepth {
		return false
	}
	tok, err := c.dec.Token()
	if err != nil {
		return false
	}
	c.count++
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			if n.obj == nil && n.val == nil {
				return false
			}
			for c.dec.More() {
				kt, err := c.dec.Token()
				key, isStr := kt.(string)
				if err != nil || !isStr {
					return false
				}
				var child *jn
				if n.obj != nil {
					child = n.obj[key]
				} else if n.keyRe.MatchString(key) {
					child = n.val
				}
				if child == nil || !c.value(child, depth+1) {
					return false
				}
			}
			end, err := c.dec.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			if n.arr == nil {
				return false
			}
			for c.dec.More() {
				if !c.value(n.arr, depth+1) {
					return false
				}
			}
			end, err := c.dec.Token()
			return err == nil && end == json.Delim(']')
		}
		return false
	case string:
		return n.str != nil && n.str.MatchString(t)
	case json.Number:
		return n.num
	case bool:
		return n.flag
	}
	return false
}

// checkJSON recognizes a JSON lockfile: the whole document matches the schema,
// the top-level object has every required key, and nothing follows it. required
// is checked by a second pass over the document's top-level keys, which the
// schema pass cannot report.
func checkJSON(schema *jn, required ...string) lockfileCheck {
	return func(r io.Reader) bool {
		data, err := io.ReadAll(r)
		if err != nil || !utf8.Valid(data) {
			return false
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.UseNumber()
		c := &jsonCheck{dec: dec}
		if !c.value(schema, 0) {
			return false
		}
		if _, err := dec.Token(); err != io.EOF {
			return false
		}
		var top map[string]json.RawMessage
		if json.Unmarshal(data, &top) != nil {
			return false
		}
		for _, k := range required {
			if _, ok := top[k]; !ok {
				return false
			}
		}
		return true
	}
}

var (
	// reTok is the characters package names, versions, ranges, URLs, paths and
	// hashes are written in. It has no quote, backslash, backtick, brace or
	// control character.
	reTok       = regexp.MustCompile("^[A-Za-z0-9._~:/?#@!$&'()*+,;=%^<>|\\- \\[\\]]{0,1000}$")
	reText      = regexp.MustCompile(`^[^\x00-\x1f\x7f"\\` + "`" + `]{0,400}$`)
	reIntegrity = regexp.MustCompile(`^(?:sha(?:1|256|384|512)-[A-Za-z0-9+/=]+)(?: sha(?:1|256|384|512)-[A-Za-z0-9+/=]+)*$`)
	reDepName   = regexp.MustCompile(`^[A-Za-z0-9@._~/\-+]{1,300}$`)
	reAnyKey    = regexp.MustCompile(`^[A-Za-z0-9@._~/\-+\\:$ ]{0,300}$`)
	rePkgPath   = regexp.MustCompile(`^[A-Za-z0-9@._~/\-+]*$`)
	reHashHex   = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{40,128}$`)
)

func tokS() *jn  { return &jn{str: reTok} }
func textS() *jn { return &jn{str: reText} }
func boolS() *jn { return &jn{flag: true} }
func numS() *jn  { return &jn{num: true} }
func strMap(v *jn) *jn {
	return &jn{keyRe: reDepName, val: v}
}
func arrOf(v *jn) *jn { return &jn{arr: v} }

// anyTree accepts any nested arrangement of token strings, numbers, booleans,
// arrays and objects: the free-form configuration (autoload, extra) some
// formats carry.
func anyTree() *jn {
	n := &jn{str: reTok, num: true, flag: true, keyRe: reAnyKey}
	n.val = n
	n.arr = n
	return n
}

var npmLockSchema = func() *jn {
	deps := &jn{}
	pkg := &jn{}
	pkg.obj = map[string]*jn{
		"name": tokS(), "version": tokS(), "resolved": tokS(),
		"integrity": {str: reIntegrity},
		"link":      boolS(), "dev": boolS(), "optional": boolS(), "devOptional": boolS(), "peer": boolS(),
		"inBundle": boolS(), "hasInstallScript": boolS(), "hasShrinkwrap": boolS(), "extraneous": boolS(),
		"bundled": boolS(), "ideallyInert": boolS(),
		"bin":                  tokS().or(strMap(tokS())),
		"license":              tokS().or(arrOf(tokS())).or(&jn{obj: map[string]*jn{"type": tokS(), "url": tokS()}}),
		"engines":              strMap(tokS()).or(arrOf(tokS())),
		"dependencies":         strMap(tokS()),
		"devDependencies":      strMap(tokS()),
		"optionalDependencies": strMap(tokS()),
		"peerDependencies":     strMap(tokS()),
		"peerDependenciesMeta": strMap(&jn{obj: map[string]*jn{"optional": boolS()}}),
		"funding":              tokS().or(&jn{obj: map[string]*jn{"url": tokS(), "type": tokS()}}).or(arrOf(tokS().or(&jn{obj: map[string]*jn{"url": tokS(), "type": tokS()}}))),
		"os":                   tokS().or(arrOf(tokS())),
		"cpu":                  tokS().or(arrOf(tokS())),
		"libc":                 tokS().or(arrOf(tokS())),
		"deprecated":           textS(),
		"workspaces":           arrOf(tokS()).or(&jn{obj: map[string]*jn{"packages": arrOf(tokS())}}),
		"bundleDependencies":   arrOf(tokS()).or(boolS()),
		"bundledDependencies":  arrOf(tokS()).or(boolS()),
		"directories":          strMap(tokS()),
		"requires":             strMap(tokS()),
		"from":                 tokS(),
		"version_":             tokS(),
	}
	// Version 1: entries keyed by package name, nested under dependencies.
	pkg.obj["dependencies"] = &jn{keyRe: reDepName, val: tokS().or(pkg)}
	deps.keyRe, deps.val = reDepName, pkg
	return &jn{obj: map[string]*jn{
		"name": tokS(), "version": tokS(), "lockfileVersion": numS(), "requires": boolS().or(strMap(tokS())),
		"packages":     {keyRe: rePkgPath, val: pkg},
		"dependencies": deps,
	}}
}()

var pipfileLockSchema = func() *jn {
	entry := &jn{obj: map[string]*jn{
		"hashes": arrOf(tokS()), "index": tokS(), "markers": tokS(), "version": tokS(),
		"extras": arrOf(tokS()), "editable": boolS(), "file": tokS(), "path": tokS(), "git": tokS(),
		"ref": tokS(), "subdirectory": tokS(), "sys_platform": tokS(), "python_version": tokS(),
	}}
	return &jn{obj: map[string]*jn{
		"_meta": {obj: map[string]*jn{
			"hash":         {obj: map[string]*jn{"sha256": tokS()}},
			"pipfile-spec": numS(),
			"requires":     {obj: map[string]*jn{"python_version": tokS(), "python_full_version": tokS()}},
			"sources":      arrOf(&jn{obj: map[string]*jn{"name": tokS(), "url": tokS(), "verify_ssl": boolS()}}),
		}},
		"default": strMap(entry), "develop": strMap(entry),
	}}
}()

var composerLockSchema = func() *jn {
	urlRef := &jn{obj: map[string]*jn{"type": tokS(), "url": tokS(), "reference": tokS(), "shasum": tokS(), "mirrors": anyTree()}}
	link := func() *jn { return &jn{keyRe: reDepName, val: tokS()} }
	person := &jn{obj: map[string]*jn{"name": textS(), "email": tokS(), "homepage": tokS(), "role": textS()}}
	pkg := &jn{obj: map[string]*jn{
		"name": tokS(), "version": tokS(), "type": tokS(), "installation-source": tokS(), "time": tokS(),
		"source": urlRef, "dist": urlRef,
		"require": link(), "require-dev": link(), "conflict": link(), "replace": link(), "provide": link(),
		"suggest":  {keyRe: reDepName, val: textS()},
		"autoload": anyTree(), "autoload-dev": anyTree(), "extra": anyTree(),
		"notification-url": tokS(), "license": arrOf(tokS()).or(tokS()),
		"authors":     arrOf(person),
		"description": textS(), "homepage": tokS(), "keywords": arrOf(textS()),
		"support":           {keyRe: reDepName, val: tokS()},
		"funding":           arrOf(&jn{obj: map[string]*jn{"url": tokS(), "type": tokS()}}),
		"bin":               arrOf(tokS()),
		"include-path":      arrOf(tokS()),
		"default-branch":    boolS(),
		"abandoned":         boolS().or(tokS()),
		"archive":           anyTree(),
		"transport-options": anyTree(),
	}}
	return &jn{obj: map[string]*jn{
		"_readme":      arrOf(textS()),
		"content-hash": tokS(),
		"packages":     arrOf(pkg), "packages-dev": arrOf(pkg),
		"aliases":           arrOf(&jn{obj: map[string]*jn{"alias": tokS(), "alias_normalized": tokS(), "version": tokS(), "package": tokS()}}),
		"minimum-stability": tokS(), "stability-flags": (&jn{keyRe: reDepName, val: numS()}).orArr(),
		"prefer-stable": boolS(), "prefer-lowest": boolS(),
		"platform": strMap(tokS()).orArr(), "platform-dev": strMap(tokS()).orArr(),
		"plugin-api-version": tokS(),
	}}
}()

// orArr lets a map also be written as an empty array, as composer does for an
// empty platform or stability-flags.
func (a *jn) orArr() *jn {
	out := *a
	out.arr = &jn{}
	return &out
}
