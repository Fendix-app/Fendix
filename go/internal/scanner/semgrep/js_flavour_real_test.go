package semgrep

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Round 6, WS-E3. The ruletests check the YAML with semgrep --test; this test
// checks what the engine itself runs, end to end through ScanRunWithOptions:
// the rules it extracts and rewrites at run time (scanner.go, the rules
// extraction), the groups and units it plans (plan.go) and the extensions
// pass. A JavaScript/TypeScript flavour split made in any of those places is
// measured here, not only in the YAML.
//
// Every JavaScript ruletest (javascript-*.ts and javascript-*.js: the cases,
// their .js mirrors, the flow-as and decorators files) is copied into a tree
// over 4 MiB, so the JavaScript group exceeds DefaultChunkBytes and runs as
// several units (heavy files alone, the rest in bulk): the shard path, which a
// small fixture never takes. Beside them, one case per source extension the
// engine selects for the JavaScript group, and per extension only the
// extensions pass evaluates (.es6, .mts, .cts, an upper-case APP.JS). For every
// rule a file's annotations speak for, the reported (file, line, rule) set
// must equal them exactly: each `ruleid:` line reported by each rule it names,
// each `ok:` line by none of them, and no line nobody annotated. As in
// semgrep --test, a ruletest's annotations speak for the rules of its own pack
// (its stem: javascript-web.ts for rules/javascript-web.yaml); the extension
// cases speak for every JavaScript pack. Other findings (another pack's rule
// on a ruletest, such as js-ssti-taint on javascript-web.ts's
// nunjucks.renderString line, which is a real template injection) are counted,
// not compared. The filler is mostly
// comment, so it adds bytes without adding code.
//
// Skipped without semgrep on PATH, and failed when FENDIX_REQUIRE_SEMGREP is set.

// wse3JSFlavourCases maps a file to its source. Each `// ruleid:` line names the
// rules that must report the next line. Besides the Express cases, the
// JavaScript-family files hold cases reachable only through the sources that
// look TypeScript-only: a NestJS parameter decorator (Babel legacy
// decorators), @Req under another name, and a Flow `as` cast. A JavaScript
// flavour that dropped those sources loses these lines here, in the engine's
// own run.
var wse3JSFlavourCases = map[string]string{
	"src/flavours/controller.js": `import { Body, Controller, Get, Headers, Param, Query, Req } from '@nestjs/common';
import { Pool } from 'pg';
const pool = new Pool();
@Controller('flavours')
export class FlavourController {
  @Get('q')
  async byQuery(@Query('k') value) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + value);
  }
  @Get('r')
  async byReq(@Req() httpReq) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + httpReq.query.k);
  }
}
`,
	"src/flavours/flow.mjs": `// @flow
import { Pool } from 'pg';
const pool = new Pool();
export async function lookupUser(req, res) {
  const { id } = (req.body as { id: string });
  // ruleid: js-sqli-taint, js-sqli-sink
  const rows = await pool.query('SELECT * FROM users WHERE id = ' + id);
  res.json(rows);
}
`,
	"src/flavours/decorated.cjs": `const { Body, Controller, Post } = require('@nestjs/common');
const { exec } = require('node:child_process');
@Controller('cjs')
class PingController {
  @Post()
  ping(@Body('host') target) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + target, () => undefined);
  }
}
module.exports = PingController;
`,
	"src/flavours/view.jsx": `const express = require('express');
const { Pool } = require('pg');
const pool = new Pool();
const router = express.Router();
router.get('/jsx', (req, res) => {
  // ruleid: js-sqli-taint, js-sqli-sink
  pool.query('SELECT * FROM users WHERE name = ' + req.query.name);
  res.end();
});
export const Banner = () => <div className="banner">ok</div>;
module.exports = router;
`,
	"src/flavours/server.cjs": `const express = require('express');
const { exec } = require('node:child_process');
const router = express.Router();
router.get('/cjs', (req, res) => {
  // ruleid: js-cmdi-taint, js-cmdi-sink
  exec('ping -c 1 ' + req.query.host, () => res.end());
});
module.exports = router;
`,
	"src/flavours/server.mjs": `import express from 'express';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');
const router = express.Router();
router.get('/mjs', async (req, res) => {
  // ruleid: js-path-traversal-taint
  const body = await fsp.readFile(path.join(UPLOAD_DIR, req.query.file), 'utf8');
  res.end(body);
});
export default router;
`,
	"src/flavours/legacy.es6": `const express = require('express');
const router = express.Router();
router.get('/es6', (req, res) => {
  // ruleid: js-open-redirect-taint
  res.redirect(req.query.next);
});
module.exports = router;
`,
	"src/flavours/routes.ts": `import express, { Request, Response } from 'express';
import { Pool } from 'pg';
const pool = new Pool();
const router = express.Router();
router.get('/ts', async (req: Request, res: Response) => {
  const name: string = String(req.query.name);
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM users WHERE name = ' + name);
  res.end();
});
export default router;
`,
	"src/flavours/page.tsx": `import express, { Request, Response } from 'express';
const router = express.Router();
router.get('/tsx', (req: Request, res: Response) => {
  // ruleid: js-xss-taint
  res.send('<p>' + req.query.note + '</p>');
});
export const Page = (): JSX.Element => <main>ok</main>;
export default router;
`,
	"src/flavours/fetcher.mts": `import express, { Request, Response } from 'express';
const router = express.Router();
router.get('/mts', async (req: Request, res: Response) => {
  // ruleid: js-ssrf-taint
  const upstream = await fetch(String(req.query.url));
  res.status(upstream.status).end();
});
export default router;
`,
	"src/flavours/render.cts": `import express = require('express');
import ejs = require('ejs');
const router = express.Router();
router.post('/cts', (req: express.Request, res: express.Response) => {
  // ruleid: js-ssti-taint
  res.send(ejs.render(req.body.template, { year: 2026 }));
});
export = router;
`,
	"src/flavours/APP.JS": `const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
router.get('/upper', (req, res) => {
  // ruleid: js-jwt-no-verify-taint
  const claims = jwt.decode(req.headers.authorization);
  res.json(claims);
});
module.exports = router;
`,
}

// wse3CommentFiller is n bytes of a JavaScript file that is one export and a long
// block comment.
func wse3CommentFiller(i, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "export const filler%d = %d;\n/*\n", i, i)
	line := strings.Repeat("lorem ipsum dolor sit amet ", 3) + "\n"
	for b.Len() < n-4 {
		b.WriteString(line)
	}
	b.WriteString("*/\n")
	return b.String()
}

// wse3AnnotatedLines returns "<file>:<line> <rule>" for every rule each
// annotation of the given kind ("ruleid" or "ok") names, keyed by the line that
// follows it.
func wse3AnnotatedLines(files map[string]string, kind string) map[string]bool {
	out := map[string]bool{}
	for rel, body := range files {
		for line, a := range wse3AnnotationsByLine(body) {
			k, ids, _ := strings.Cut(a, ": ")
			if k != kind {
				continue
			}
			for _, id := range strings.Split(ids, ", ") {
				out[fmt.Sprintf("%s:%d %s", rel, line+1, id)] = true
			}
		}
	}
	return out
}

// wse3JSPackRuleIDs maps every rule id of the JavaScript packs, taint or not,
// to its pack's stem.
func wse3JSPackRuleIDs(t *testing.T) map[string]string {
	t.Helper()
	rules, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		t.Fatal(err)
	}
	packs, err := fs.Glob(rules, "javascript-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, pack := range packs {
		data, err := fs.ReadFile(rules, pack)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodePack(data)
		if err != nil {
			t.Fatalf("parse %s: %v", pack, err)
		}
		for _, r := range decoded {
			out[r.ID] = strings.TrimSuffix(pack, ".yaml")
		}
	}
	return out
}

// wse3SpeaksFor reports whether the annotations of the file at rel cover the
// rules of pack: a ruletest covers its own pack, an extension case all of them.
func wse3SpeaksFor(rel, pack string) bool {
	name, ok := strings.CutPrefix(rel, "src/ruletests/")
	if !ok {
		return true
	}
	return strings.SplitN(name, ".", 2)[0] == pack
}

// wse3Covered keeps the "<file>:<line> <rule>" keys whose file speaks for the
// rule's pack.
func wse3Covered(keys map[string]bool, packOf map[string]string) map[string]bool {
	out := map[string]bool{}
	for k := range keys {
		loc, rule, _ := strings.Cut(k, " ")
		file := loc[:strings.LastIndex(loc, ":")]
		if pack, ok := packOf[rule]; ok && wse3SpeaksFor(file, pack) {
			out[k] = true
		}
	}
	return out
}

func TestRealSemgrepReportsEveryJavaScriptFlavourThroughTheShardPath(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)

	// The annotated files: every JavaScript ruletest, and the extension cases.
	annotated := map[string]string{}
	tests := os.DirFS("ruletests")
	for _, glob := range []string{"javascript-*.ts", "javascript-*.js"} {
		names, err := fs.Glob(tests, glob)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			data, err := fs.ReadFile(tests, name)
			if err != nil {
				t.Fatal(err)
			}
			annotated["src/ruletests/"+name] = string(data)
		}
	}
	if n := len(annotated); n < 23 {
		t.Fatalf("found %d JavaScript ruletests; want every javascript-*.ts and .js (at least 23: 10 .ts, their 10 mirrors, 3 flow-as)", n)
	}
	for rel, body := range wse3JSFlavourCases {
		annotated[rel] = body
	}

	root := t.TempDir()
	tree := map[string]string{}
	for rel, body := range annotated {
		tree[rel] = body
	}
	// Three heavy files (each runs alone) and bulk filler: over 4 MiB in all.
	for i := 0; i < 3; i++ {
		tree[fmt.Sprintf("src/vendor/heavy%d.js", i)] = wse3CommentFiller(i, 400<<10)
	}
	for i := 3; i < 33; i++ {
		tree[fmt.Sprintf("src/lib/part%d.js", i)] = wse3CommentFiller(i, 110<<10)
	}
	writeTree(t, root, tree)
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	if total <= 4<<20 {
		t.Fatalf("the tree is %d bytes; it must exceed 4 MiB to take the shard path", total)
	}

	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{})
	if err != nil {
		t.Fatalf("ScanRunWithOptions: %v", err)
	}
	if len(run.Units) < 2 {
		t.Fatalf("the plan made %d unit(s) %v; a tree over DefaultChunkBytes must take the shard path", len(run.Units), run.Units)
	}
	if run.Coverage.Lost() {
		t.Errorf("files lost evaluation: %d (%v)", run.Coverage.LostFiles(), run.Report)
	}

	packOf := wse3JSPackRuleIDs(t)
	all := map[string]bool{}
	for _, f := range run.Findings {
		all[filepath.ToSlash(f.Endpoint)+" "+f.RuleID] = true
	}
	got := wse3Covered(all, packOf)
	others := len(all) - len(got)
	want := wse3Covered(wse3AnnotatedLines(annotated, "ruleid"), packOf)
	okLines := wse3Covered(wse3AnnotatedLines(annotated, "ok"), packOf)
	if unknown := len(wse3AnnotatedLines(annotated, "ruleid")) - len(want); unknown != 0 {
		t.Errorf("%d ruleid annotations name a rule that is not in the file's own JavaScript pack", unknown)
	}
	var missed, okReported, extra []string
	for k := range want {
		if !got[k] {
			missed = append(missed, k)
		}
	}
	for k := range got {
		switch {
		case want[k]:
		case okLines[k]:
			okReported = append(okReported, k)
		default:
			extra = append(extra, k)
		}
	}
	sort.Strings(missed)
	sort.Strings(okReported)
	sort.Strings(extra)
	t.Logf("units %v; %d annotated files; %d ruleid and %d ok annotations compared; %d findings outside the annotating pack not compared",
		run.Units, len(annotated), len(want), len(okLines), others)
	if len(missed) > 0 || len(okReported) > 0 || len(extra) > 0 {
		t.Errorf("missed (ruleid, not reported) %d: %q\nok lines reported %d: %q\nunannotated lines reported %d: %q",
			len(missed), missed, len(okReported), okReported, len(extra), extra)
	}
}
