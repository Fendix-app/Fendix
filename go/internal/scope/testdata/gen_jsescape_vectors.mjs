// Generator of testdata/jsescape_vectors.json (R6-E7a, Release Closure Sprint, WS-C2).
//
// Ground truth is not this repository's lexer: it is the TypeScript scanner
// and parser (typescript.createSourceFile, then every leaf token of the tree). A
// leaf token that is not a string literal, a template part, a regular-expression
// literal, JSX text, a JSDoc node (a comment) or a non-text file marker, and whose source text holds a
// backslash, is an escape in identifier position (`oracle`). Node itself is the second witness: a vector
// that holds a payload runs it in a fresh vm context, and `node_runs` records
// whether the payload executed (true), did not (false) or the source is not
// valid JavaScript (null). The payloads only set a global flag.
//
// A vector's `expect` is what jsescape.go must answer. It equals the oracle's
// answer unless the vector names a `deviation`, which is only ever the
// conservative direction (the file is reported lost where the oracle sees a
// regular expression or a comment): a reading the lexer cannot rule out is read
// both ways and the file is lost when either one finds an escape.
//
// Run (host with node and a TypeScript checkout; the engine images have neither):
//
//     FENDIX_TS=/path/to/node_modules/typescript \
//       node gen_jsescape_vectors.mjs /path/to/go/internal/scope/testdata
//
// The file is written next to this script by default. Never edit it by hand.

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const tsPath = process.env.FENDIX_TS || '/Users/asaied/WorkDir/Fendix/fendix-services/fendix_frontend/node_modules/typescript';
const ts = require(tsPath);
const babelPath = process.env.FENDIX_BABEL || '/Users/asaied/WorkDir/Fendix/fendix-services/fendix_frontend/node_modules/@babel/parser';
const babel = require(babelPath);
// Flow is not TypeScript: for a vector marked `flow` the oracle is Babel's flow+jsx tokenizer. A token that is
// not a string, template part, regular-expression literal, JSX text or comment and whose text holds a backslash
// is an escape in identifier position.
const BABEL_SAFE = new Set(['string', 'template', 'regexp', 'jsxText', 'CommentBlock', 'CommentLine', 'eof']);
function babelHits(text) {
  const ast = babel.parse(text, { sourceType: 'unambiguous', plugins: ['flow', 'jsx'], tokens: true, errorRecovery: false });
  const hits = [];
  for (const t of ast.tokens) {
    const label = typeof t.type === 'string' ? t.type : t.type.label;
    if (BABEL_SAFE.has(label)) continue;
    if (text.slice(t.start, t.end).includes(BSL)) hits.push(t.start);
  }
  return hits;
}
const K = ts.SyntaxKind;
const SAFE = new Set([
  K.StringLiteral, K.NoSubstitutionTemplateLiteral, K.TemplateHead, K.TemplateMiddle, K.TemplateTail,
  K.RegularExpressionLiteral, K.JsxText, K.JsxTextAllWhiteSpaces, K.EndOfFileToken,
]);
const SCRIPT_KIND = {
  '.js': ts.ScriptKind.JS, '.jsx': ts.ScriptKind.JSX, '.mjs': ts.ScriptKind.JS, '.cjs': ts.ScriptKind.JS,
  '.es6': ts.ScriptKind.JS, '.ts': ts.ScriptKind.TS, '.mts': ts.ScriptKind.TS, '.cts': ts.ScriptKind.TS,
  '.tsx': ts.ScriptKind.TSX,
};

export function oracle(text, ext) {
  const sf = ts.createSourceFile('f' + ext, text, ts.ScriptTarget.Latest, false, SCRIPT_KIND[ext] ?? ts.ScriptKind.JS);
  const hits = [];
  const walk = (n) => {
    const kids = n.getChildren(sf);
    if (kids.length === 0) {
      if (SAFE.has(n.kind) || (n.kind >= K.FirstJSDocNode && n.kind <= K.LastJSDocNode) || n.kind === K.NonTextFileMarkerTrivia) return;
      const s = n.getStart(sf, true);
      if (text.slice(s, n.end).includes('\\')) hits.push(s);
      return;
    }
    for (const c of kids) walk(c);
  };
  walk(sf);
  return hits;
}

const HIT = 'globalThis.__HIT=1';
// A payload that runs when an escaped identifier is read as `eval`.
const EV = String.raw`\u0065val("${HIT}")`;
const LS = '\u2028';
const V = [];
const add = (id, ext, text, note, deviation, flow = false) => V.push({ id, ext, text, note, deviation, flow });
// Pieces spelled without a literal escape sequence, so no tool in a pipeline rewrites them.
const BSL = String.fromCharCode(92);
const U41 = BSL + 'u0041'; // an escape for A
const EX = BSL + 'u0065xec'; // an escaped exec

// --- an escape in identifier position: every one of these is lost evaluation ---
add('ident-bare', '.js', EV + ';', 'an escaped eval called as a function');
add('ident-bare-exec', '.js', String.raw`const cp = { \u0065xec(c) { globalThis.__HIT = 1 } }; cp.\u0065xec("x");`, 'an escaped exec on an object');
add('ident-dot', '.js', String.raw`globalThis.\u0065val("${HIT}");`, 'the name after a dot');
add('ident-window-dot', '.js', String.raw`window.\u0065val("x")`, 'window.eval spelled with an escape');
add('ident-decl', '.js', String.raw`const \u0066 = 7; f;`, 'a declaration (redeclares f)');
add('ident-brace-form', '.js', String.raw`\u{65}val("${HIT}");`, 'the \\u{...} form');
add('ident-brace-padded', '.js', String.raw`\u{0000065}val("${HIT}");`, 'the \\u{...} form with leading zeros');
add('ident-brace-upper', '.js', String.raw`\u{0000065}val("${HIT}"); var \u{45}x;`, 'hex digits in either case');
add('ident-hex-upper', '.js', String.raw`\u0045xec; var \u00E9;`, 'upper-case hex digits');
add('ident-keyword', '.js', String.raw`\u0069f (true) { }`, 'an escaped keyword (a syntax error for the engine, an escape for the lexer)');
add('ident-prop-key', '.js', String.raw`var o = { \u0061: 1 };`, 'an object property key');
add('ident-prop-key-string-call', '.js', String.raw`var o = { "a": 1, \u0062() {} };`, 'a method name');
add('ident-label', '.js', String.raw`\u0061: for (;;) { break \u0061; }`, 'a label and its break');
add('ident-optional-chain', '.js', String.raw`var a = {}; a?.\u0062;`, 'the name after ?.');
add('ident-class-member', '.js', String.raw`class A { \u0061() {} static \u0062 = 1 }`, 'class members');
add('ident-private-name', '.js', String.raw`class A { #\u0061 = 1 }`, 'a private name');
add('ident-subst', '.js', '`x ${ ' + EV + ' } y`;', 'code inside a template substitution');
add('ident-subst-nested', '.js', '`a ${ `b ${ ' + EV + ' } \\u0041` } \\u0042`;', 'nested templates: the escape in the inner substitution');
add('ident-after-division', '.js', String.raw`var a = 4, b = 2; a / b / \u0063;`, 'division, then an escaped identifier');
add('ident-after-division-eval', '.js', String.raw`var x = 8 / 2 / \u0065val("${HIT}");`, 'division, then an escaped eval call');
add('ident-after-paren', '.js', String.raw`var a = 4, b = 2; (a) / \u0062 / 1;`, 'division after a closing parenthesis');
add('ident-after-call', '.js', String.raw`var f = () => 4, b = 2; f() / \u0062 / 1;`, 'division after a call');
add('ident-after-bracket', '.js', String.raw`var a = [4], b = 2; a[0] / \u0062 / 1;`, 'division after a closing bracket');
add('ident-after-number', '.js', String.raw`var b = 2; 8 / \u0062 / 1;`, 'division after a number');
add('ident-after-string', '.js', String.raw`var b = 2; "8" / \u0062 / 1;`, 'division after a string');
add('ident-after-template', '.js', '`8` / \\u0062 / 1;', 'division after a template');
add('ident-after-regex', '.js', String.raw`var b = 2; /x/ / \u0062 / 1;`, 'division after a regular expression');
add('ident-after-postfix', '.js', String.raw`var i = 4, b = 2; i++ / \u0062 / 1;`, 'division after a postfix ++');
add('ident-after-object-postfix', '.js', String.raw`var b = 2, x = {a: 1}++ / \u0062 / 1;`, 'a postfix ++ after an object literal, then division: a regex reading would hide the escape');
add('ident-after-function-body-postfix', '.ts', String.raw`var b = 2, x = function () {}++ / \u0062 / 1;`, 'a postfix ++ after a function body, then division');
add('ident-after-object-literal', '.js', String.raw`var b = 2, x = {} / \u0062 / 1;`, 'division after an object literal');
add('ident-after-function-body', '.js', String.raw`var b = 2, x = function () {} / \u0062 / 1;`, 'division after a function expression: a regex reading would hide the escape');
add('ident-after-arrow-block', '.js', String.raw`var b = 2, x = (() => {}) / \u0062 / 1;`, 'division after a parenthesised arrow function');
add('ident-keyword-property', '.js', String.raw`var o = { in: 4, return: 4 }; o.in / \u0062 / 1; o.return / \u0062 / 1;`, 'a keyword after a dot is a property name, so / divides');
add('ident-after-if-head-else-branch', '.js', String.raw`if (false) 1; else \u0062 = 1;`, 'an escaped name after else');
add('ident-ts-non-null', '.ts', String.raw`declare const a: number; a! / \u0062 / 1;`, 'division after TypeScript non-null assertion');
add('ident-ts-assertion', '.ts', String.raw`var a = <number>4 / \u0062 / 1;`, 'a type assertion, then division');
add('ident-ts-generic', '.ts', String.raw`function f<T>(x: T) { return x; } f<number>(1) / \u0062 / 1;`, 'a generic call, then division');
add('ident-tsx-generic-arrow', '.tsx', String.raw`const f = <T,>(x: T) => x; \u0065val("x");`, 'a generic arrow function is not JSX; the escape after it is code');
add('ident-tsx-generic-extends', '.tsx', String.raw`const f = <T extends object>(x: T) => x; \u0065val("x");`, 'a generic arrow function with a constraint');
add('ident-hashbang', '.js', '#!/usr/bin/env node\n' + EV + ';', 'code after a hashbang line');
add('ident-bom', '.js', '\ufeff' + EV + ';', 'code after a byte-order mark');
add('ident-after-line-comment', '.js', '// c\n' + EV + ';', 'code after a line comment');
add('ident-after-block-comment', '.js', '/* c \\u0041 */ ' + EV + ';', 'code after a block comment');
add('ident-line-comment-ends-at-ls', '.js', '// c' + LS + EV + ';', 'U+2028 ends a // comment: the code after it runs');
add('ident-line-comment-ends-at-cr', '.js', '// c\r' + EV + ';', 'a bare CR ends a // comment');
add('ident-line-comment-ends-at-crlf', '.js', '// c\r\n' + EV + ';', 'CRLF ends a // comment');
add('ident-string-ends-at-newline', '.js', '"unterminated\n' + EV + ';', 'an unterminated string ends at the line end (a syntax error; the escape is still in code)');
add('ident-string-continuation-then-code', '.js', '"a\\\n b"; ' + EV + ';', 'a string with a line continuation, then code');
add('ident-regex-flags-then-code', '.js', String.raw`var r = /a/g; ${EV};`, 'code after a regular expression with flags');
add('ident-regex-class-then-code', '.js', String.raw`var r = /[/]/; ${EV};`, 'code after a regex whose class holds a slash');
add('ident-div-chain-then-regex', '.js', String.raw`var a = 8, b = 2, c = 2; a / b / c; ${EV}; /[\u0041]/.test("A");`, 'division, an escaped call, then a regex');
add('ident-surrogate-pair', '.js', String.raw`var \ud835\udc9c = 1;`, 'an escaped surrogate pair as an identifier (rejected by the engine; an escape for the lexer)');
add('ident-raw-astral-then-escape', '.js', 'var \u{1d49c} = 1; ' + EV + ';', 'a raw astral identifier, then an escape');
add('ident-jsx-expression', '.jsx', 'x = <div>{' + EV + '}</div>;', 'code inside a JSX expression container');
add('ident-jsx-attribute-expression', '.jsx', 'x = <a b={' + EV + '} />;', 'code in a JSX attribute value');
add('ident-jsx-spread', '.jsx', 'x = <a {...\\u0061} />;', 'a spread attribute');
add('ident-jsx-after-element', '.jsx', 'x = <b/>; ' + EV + ';', 'code after a self-closing element');
add('ident-jsx-after-nested', '.jsx', 'x = <a><b>t</b><c/></a>; ' + EV + ';', 'code after nested elements');
add('ident-jsx-text-apostrophe-then-code', '.jsx', "x = <p>It's</p>; " + EV + ';', 'an apostrophe in JSX text must not hide the code after the element');
add('ident-jsx-text-backtick-then-code', '.jsx', 'x = <p>a ` b</p>;\n' + EV + ';', 'a backtick in JSX text must not open a template');
add('ident-jsx-text-slashes-then-code', '.jsx', 'x = <p>http://x /* y</p>;\n' + EV + ';', 'comment openers in JSX text are text');
add('ident-jsx-closing-tag-slash', '.jsx', 'x = <a>t</a>; y = 4 / 2 / \\u0062;', 'the slash of a closing tag is not a regex');
add('ident-jsx-fragment', '.jsx', 'x = <>t</>; ' + EV + ';', 'a fragment');
add('ident-jsx-attr-string-then-code', '.jsx', 'x = <a t="\\u0041" u=\'q\'/>; ' + EV + ';', 'an attribute string holds an escape, the code after the tag holds another');
add('ident-tsx-element-after-arrow', '.tsx', 'const f = () => <div>t</div>; ' + EV + ';', 'JSX after an arrow');
add('ident-js-jsx', '.js', 'x = <div>t {' + EV + '}</div>;', 'JSX in a .js file');
add('ident-mjs', '.mjs', 'export const x = 1; ' + EV + ';', 'a module');
add('ident-cjs', '.cjs', 'module.exports = 1; ' + EV + ';', 'CommonJS');
add('ident-mts', '.mts', 'export const x: number = 1; ' + EV + ';', 'a TypeScript module');
add('ident-cts', '.cts', 'export = 1; ' + EV + ';', 'CommonJS TypeScript');
add('ident-es6', '.es6', EV + ';', 'an .es6 file');
add('ident-upper-extension', '.JS', EV + ';', 'the extension is matched without regard to case');

// --- the doubts: read both ways, lost when either reading finds an escape ---
add('doubt-html-open-comment', '.js', 'a = 1 <!-- ' + EV + '\n', 'in a script <!-- starts a comment, in a module it is operators: the oracle (operators) and the lexer (both readings) agree');
add('doubt-html-open-comment-backtick', '.js', 'a = 1 <!-- `\n' + EV + ';\n', 'a script: the comment ends the line and the call after it runs; a module: a template opens', { expect: true, reason: 'the oracle reads the backtick as a template that hides the call; Node (script) runs it' });
add('doubt-html-close-comment', '.js', 'a = 1\n--> ' + EV + '\n', 'in a script --> at the head of a line starts a comment, in a module it is operators: the oracle and the lexer agree');
add('doubt-html-close-comment-backtick', '.js', 'a = 1\n--> `\n' + EV + ';\n', 'a script: --> at the head of a line starts a comment that ends the line, then the call after it runs; a module: a template opens', { expect: true, reason: 'the oracle reads --> as operators and the backtick as a template that hides the call; Node (script) runs it' });
add('doubt-html-open-comment-mjs', '.mjs', 'a = 1 <!-- ' + EV + '\n', 'a module: <!-- is operators');
add('doubt-regex-after-function-body', '.js', 'function f() {}\n/[\\u0041]/.test(y);', 'a regex at the start of a statement after a function declaration: the body of a function declaration and of a function expression look alike', { expect: true, reason: 'after } of a function body the next / is a regex or a division: both readings are explored and the division reading reaches the escape' });
add('doubt-regex-after-class-body', '.js', 'class A {}\n/[\\u0041]/.test(y);', 'a regex after a class declaration', { expect: true, reason: 'a class body and a class expression look alike: both readings are explored' });
add('doubt-regex-after-labelled-block', '.js', 'a: { }\n/[\\u0041]/.test(y);', 'a regex after a labelled block', { expect: true, reason: 'a { after a colon is a block or an object: both readings are explored' });
add('doubt-regex-after-block-then-code', '.js', 'if (x) {}\n/[/]/.test(y); ' + EV + ';', 'a regex after a block, then code');
add('doubt-regex-after-of', '.js', 'for (const m of /[\\u0041]/g.exec(y)) {}', 'a regex after the word of', { expect: true, reason: 'of is a keyword in a for loop and a name elsewhere: both readings are explored' });
add('doubt-regex-after-yield', '.js', 'function* g() { yield /[\\u0041]/; }', 'a regex after yield', { expect: true, reason: 'yield is a keyword in a generator and a name elsewhere: both readings are explored' });
add('doubt-regex-after-await', '.js', 'async function g() { await /[\\u0041]/; }', 'a regex after await', { expect: true, reason: 'await is a keyword in an async function and a name elsewhere: both readings are explored' });
add('doubt-division-after-await-name', '.js', 'var await = 4, b = 2; await / \\u0062 / 1;', 'await as a plain name, then a division: the regex reading would hide the escape');
add('doubt-division-after-of-name', '.js', 'var of = 4, b = 2; of / \\u0062 / 1;', 'of as a plain name, then a division');
add('doubt-division-after-yield-name', '.js', 'var yield = 4, b = 2; yield / \\u0062 / 1;', 'yield as a plain name, then a division');
add('doubt-ts-non-null-after-brace', '.ts', 'var o = {a: 1}; var r = o!\n/ 2;', 'a non-null assertion before a line break');

// --- no escape in identifier position: none of these may be lost ---
add('none-plain', '.js', 'var a = 1; a / 2 / 3;', 'plain code');
add('none-no-backslash', '.ts', 'const a: number = 1;', 'no backslash at all');
add('none-string-dq', '.js', 'x = "\\u0041";', 'a double-quoted string');
add('none-string-sq', '.js', "x = '\\u0042';", 'a single-quoted string');
add('none-string-brace', '.js', 'x = "\\u{41}\\u{0000041}";', 'a string with \\u{...}');
add('none-string-continuation', '.js', 'x = "a\\\n\\u0041";', 'a string with a line continuation');
add('none-string-comment-openers', '.js', 'x = "// \\u0041 /* \\u0042"; y = 1;', 'comment openers inside a string');
add('none-string-quote-escaped', '.js', 'x = "\\"\\u0041\\""; y = \'\\\'\\u0042\\\'\';', 'escaped quotes inside strings');
add('none-line-comment', '.js', '// \\u0041\nvar a;', 'a line comment');
add('none-block-comment', '.js', '/* \\u0041 \n \\u0042 */ var a;', 'a block comment');
add('none-block-comment-quotes', '.js', '/* " \' ` \\u0041 */ var a;', 'a block comment with quotes');
add('none-hashbang', '.js', '#!/usr/bin/env node \\u0041\nvar a;', 'a hashbang line');
add('none-template-text', '.js', 'x = `\\u0041 \\u{42}`;', 'template text');
add('none-template-escaped-backtick', '.js', 'x = `\\`\\u0041`;', 'an escaped backtick in template text');
add('none-template-dollar', '.js', 'x = `$\\u0041 ${1} $ {\\u0042}`;', 'a dollar that opens nothing, and text after a substitution');
add('none-template-string-in-subst', '.js', 'x = `a ${ "\\u0041" } \\u0042 ${ y } \\u0043`;', 'a string inside a substitution, text around it');
add('none-template-nested-text', '.js', 'x = `a ${ `b \\u0041 ${ 1 } \\u0042` } \\u0043`;', 'nested template text');
add('none-template-regex-in-subst', '.js', 'x = `a ${ /\\u0041/.test(y) } b`;', 'a regex inside a substitution');
add('none-template-brace-in-subst', '.js', 'x = `a ${ { b: 1 }.b } \\u0041`;', 'an object literal inside a substitution');
add('none-regex-after-return', '.js', 'function f(x) { return /[\\u0041-\\u005a]/.test(x) }', 'a regex after return');
add('none-regex-after-paren', '.js', 'x = f(/[\\u0041]/);', 'a regex after (');
add('none-regex-after-eq', '.js', 'x = /[\\u0041]/;', 'a regex after =');
add('none-regex-after-comma', '.js', 'x = [1, /[\\u0041]/];', 'a regex after ,');
add('none-regex-after-colon', '.js', 'x = { a: /[\\u0041]/ };', 'a regex after :');
add('none-regex-after-bracket', '.js', 'x = [/[\\u0041]/];', 'a regex after [');
add('none-regex-after-not', '.js', 'x = !/[\\u0041]/.test(y);', 'a regex after !');
add('none-regex-after-and', '.js', 'x = a && /[\\u0041]/.test(y) || /\\u0042/.test(y);', 'a regex after && and ||');
add('none-regex-after-question', '.js', 'x = a ? /[\\u0041]/ : /\\u0042/;', 'a regex after ? and :');
add('none-regex-after-arrow', '.js', 'f = (s) => /[\\u0041]/.test(s);', 'a regex after =>');
add('none-regex-after-typeof', '.js', 'x = typeof /[\\u0041]/;', 'a regex after typeof');
add('none-regex-after-void-delete-new', '.js', 'void /\\u0041/; delete /\\u0041/.x; new /\\u0041/.constructor();', 'a regex after void, delete and new');
add('none-regex-after-in-instanceof', '.js', 'x = a in /\\u0041/ || a instanceof /\\u0042/;', 'a regex after in and instanceof');
add('none-regex-after-case-else-do', '.js', 'switch (x) { case /\\u0041/: break; } if (a) 1; else /\\u0042/.test(y); do /\\u0043/.test(y); while (0);', 'a regex after case, else and do');
add('none-regex-after-if-head', '.js', 'if (x) /[\\u0041]/.test(y);', 'a regex after the head of an if');
add('none-regex-after-while-head', '.js', 'while (x) /[\\u0041]/.test(y);', 'a regex after the head of a while');
add('none-regex-after-for-head', '.js', 'for (;;) /[\\u0041]/.test(y);', 'a regex after the head of a for');
add('none-regex-after-for-await-head', '.js', 'async function f() { for await (const a of b) /[\\u0041]/.test(a); }', 'a regex after the head of a for await');
add('none-regex-after-statement-block', '.js', '{ a; }\n/[\\u0041]/.test(y);', 'a regex after a block statement');
add('none-regex-after-if-block', '.js', 'if (x) { a; }\n/[\\u0041]/.test(y);', 'a regex after the block of an if');
add('none-regex-after-else-block', '.js', 'if (x) { a; } else { b; }\n/[\\u0041]/.test(y);', 'a regex after the block of an else');
add('none-regex-after-for-block', '.js', 'for (;;) { break; }\n/[\\u0041]/.test(y);', 'a regex after the block of a for');
add('none-regex-after-while-block', '.js', 'while (x) { a; }\n/[\\u0041]/.test(y);', 'a regex after the block of a while');
add('none-regex-after-do-block', '.js', 'do { a; } while (x)\n/[\\u0041]/.test(y);', 'a regex after a do-while');
add('none-regex-after-switch-block', '.js', 'switch (x) { case 1: break; }\n/[\\u0041]/.test(y);', 'a regex after the block of a switch');
add('none-regex-after-try-catch-block', '.js', 'try { a; } catch (e) { b; } finally { c; }\n/[\\u0041]/.test(y);', 'a regex after try, catch and finally blocks');
add('none-regex-after-arrow-block', '.js', 'f = () => { a; }\n/[\\u0041]/.test(y);', 'a regex statement after an arrow function body');
add('none-regex-after-nested-blocks', '.js', 'if (x) { { a; } }\n/[\\u0041]/.test(y);', 'a regex after nested blocks');
add('none-regex-after-block-with-object-inside', '.js', 'if (x) { y = {a: 1}; }\n/[\\u0041]/.test(y);', 'a regex after a block that holds an object literal');
add('none-regex-after-semicolon', '.js', 'a = 1; /[\\u0041]/.test(y);', 'a regex after ;');
add('none-regex-after-brace-open', '.js', 'function f() { /[\\u0041]/.test(y); }', 'a regex after {');
add('none-regex-after-spread-operators', '.js', 'x = [...a, ...(/[\\u0041]/.exec(y))]; z = a + /\\u0042/.source; w = a * /\\u0043/.lastIndex;', 'a regex after operators');
add('none-regex-class-slash', '.js', 'x = /[/]\\u0065/;', 'a slash inside a character class does not end the regex');
add('none-regex-class-slash-escaped-bracket', '.js', 'x = /[\\]/]\\u0065/;', 'an escaped bracket inside a class');
add('none-regex-escaped-slash', '.js', 'x = /\\/\\u0065/;', 'an escaped slash');
add('none-regex-flags', '.js', 'x = /\\u0041/gi.test(y);', 'a regex with flags');
add('none-regex-quotes-and-backticks', '.js', "x = /['\"`]\\u0041/;", 'quotes and a backtick inside a regex');
add('none-regex-line-comment-openers', '.js', 'x = /\\/\\/ \\u0041 \\/*/;', 'comment openers inside a regex');
add('none-regex-in-template-subst-after-brace', '.js', 'x = `${ {a: 1}.a / 2 }`;', 'division in a substitution');
add('none-regex-mixed-with-division', '.js', 'var a = 8, b = 2; var q = a / b / 2; var r = /[\\u0041]/.test("A") ? a / b : 1;', 'divisions and a regex on one line');
add('none-division-then-string', '.js', 'x = a / b / "\\u0041";', 'division, then a string');
add('none-division-then-template', '.js', 'x = a / b / `\\u0041`;', 'division, then a template');
add('none-division-then-comment', '.js', 'x = a / b; // \\u0041\n/* \\u0042 */', 'division, then comments');
add('none-assign-div', '.js', 'x /= 2; y = /=\\u0041/;', 'a division assignment, and a regex that starts with =');
add('none-prefix-after-block', '.js', 'if (a) {}\n++b;\n/[\\u0041]/.test(y);', 'a prefix ++ at the start of a statement after a block, then a regex');
add('none-after-postfix-then-regex', '.js', 'i++\n;/[\\u0041]/.test(y);', 'a regex after a postfix operator and a semicolon');
add('none-jsx-text', '.jsx', 'x = <div>\\u0041 text</div>;', 'a JSX text node');
add('none-jsx-text-entities', '.jsx', 'x = <div>a &amp; \\u00a0 b</div>;', 'JSX text with an entity and an escape');
add('none-jsx-text-apostrophe', '.jsx', "x = <p>don't \\u0041 it's</p>;", 'apostrophes and an escape in JSX text');
add('none-jsx-text-backtick', '.jsx', 'x = <p>use `\\u0041` here</p>;', 'backticks in JSX text');
add('none-jsx-text-comment-openers', '.jsx', 'x = <p>http://a.b /* \\u0041 */ // \\u0042</p>;', 'comment openers in JSX text');
add('none-jsx-text-braces-in-string', '.jsx', 'x = <p>{"\\u0041"} \\u0042 {`\\u0043`}</p>;', 'JSX text around expression containers that hold strings');
add('none-jsx-nested', '.jsx', 'x = <ul><li>\\u0041</li><li>b <b>\\u0042</b></li></ul>;', 'nested elements');
add('none-jsx-fragment', '.jsx', 'x = <>\\u0041</>;', 'a fragment');
add('none-jsx-attribute-string', '.jsx', 'x = <a title="\\u0041" alt=\'\\u0042\' />;', 'attribute strings');
add('none-jsx-attribute-string-backslash-quote', '.jsx', 'x = <a title="a\\" b="\\u0041" />;', 'a JSX attribute string has no escapes, so a backslash before the quote does not continue it');
add('none-jsx-comment-in-expression', '.jsx', 'x = <p>{/* \\u0041 */}</p>;', 'a comment in an expression container');
add('none-jsx-expression-regex', '.jsx', 'x = <p>{/\\u0041/.test(s) ? "a" : "b"}</p>;', 'a regex in an expression container');
add('none-jsx-closing-slash-divide', '.jsx', 'x = <a>t</a>; y = 4 / 2 / 1; z = /[\\u0041]/;', 'a closing tag, a division, a regex');
add('none-jsx-self-closing-regex-after', '.jsx', 'x = <a/>; y = /[\\u0041]/;', 'a regex after a self-closing element');
add('none-jsx-in-arrow', '.jsx', 'f = () => <div>\\u0041</div>;', 'JSX after an arrow');
add('none-jsx-conditional', '.jsx', 'x = a ? <b>\\u0041</b> : <c>\\u0042</c>;', 'JSX in a conditional');
add('none-jsx-and', '.jsx', 'x = a && <b>\\u0041</b>;', 'JSX after &&');
add('none-jsx-return', '.jsx', 'function f() { return <b>\\u0041</b>; }', 'JSX after return');
add('none-jsx-return-paren', '.jsx', 'function f() { return (\n  <b>\\u0041</b>\n); }', 'JSX in parentheses');
add('none-jsx-map', '.jsx', 'x = a.map((i) => <li key={i}>\\u0041 {i}</li>);', 'JSX in a callback');
add('none-jsx-member-name', '.jsx', 'x = <a.b c-d="\\u0041">\\u0042</a.b>;', 'a member tag name and a hyphenated attribute');
add('none-jsx-namespaced', '.jsx', 'x = <svg:rect xlink:href="' + U41 + '">text</svg:rect>;', 'namespaced names, an escape in an attribute string');
add('doubt-jsx-namespaced-text', '.jsx', 'x = <svg:rect>' + U41 + '</svg:rect>;', 'a namespaced tag name: the colon could also be a Flow type parameter bound, so the lexer reads the text both ways', { expect: true, reason: 'after <name: the text could be the start of a Flow generic arrow function (<T: Bound>(x) => x): both readings are explored and the operator reading reaches the escape' });
add('none-jsx-attr-element', '.jsx', 'x = <a b=<c>\\u0041</c> />;', 'an element as an attribute value');
add('none-tsx-text', '.tsx', 'const x = <div>\\u0041 {n as number}</div>;', 'JSX text in a .tsx file');
add('none-tsx-generic-arrow-string', '.tsx', 'const f = <T,>(x: T) => x; var s = "\\u0041";', 'a generic arrow function, then a string');
add('none-tsx-generic-extends-string', '.tsx', 'const f = <T extends object>(x: T) => x; var s = "\\u0041";', 'a constrained generic arrow function, then a string');
add('none-ts-assertion-string', '.ts', 'var a = <string>"\\u0041";', 'a type assertion before a string');
add('none-ts-generic-regex', '.ts', 'var r = f<number>(/[\\u0041]/);', 'a regex after a generic call opens');
add('none-ts-non-null-division', '.ts', 'declare const a: number; var q = a! / 2 / 1; var s = "\\u0041";', 'a non-null assertion, then a division');
add('none-ts-not-equal', '.ts', 'var q = a !== /[\\u0041]/;', 'a regex after !==');
add('none-ts-prefix-not-newline', '.ts', 'var a = 1\n!/[\\u0041]/.test(y);', 'a prefix ! after a line break, then a regex');
add('none-ts-decorator', '.ts', '@dec("\\u0041") class A {}', 'a decorator with a string');
add('none-js-in-ts-regex', '.ts', 'const re: RegExp = /^[\\u0080-\\uFFFF]+$/;', 'a regex typed in TypeScript');
add('none-minified-style', '.js', 'var a=1,b=2,c=a/b/2,d=/[\\u0041]/.test("A"),e=c/d;', 'minified code: divisions and a regex');
add('none-keyword-property-regex-not', '.js', 'x = o.return / 2 / 1; y = /\\u0041/;', 'a keyword used as a property name, then a regex');
add('none-label-and-ternary', '.js', 'a: for (;;) { b = c ? /\\u0041/ : 1; break a; }', 'a label and a ternary');
add('none-class-and-template', '.js', 'class A { x = `\\u0041`; static y = /\\u0042/; }', 'class fields');
add('none-line-comment-not-ended-by-other-chars', '.js', '// a\u00a0\\u0041 \u200b \\u0042\nx;', 'NBSP and a zero-width space do not end a // comment');
add('none-html-comment-text-in-string', '.js', 'x = "<!-- \\u0041"; y = "-->";', 'HTML comment markers inside strings');
add('none-html-comment-in-template', '.js', 'x = `<!-- \\u0041 -->`;', 'HTML comment markers inside a template');
add('none-html-comment-in-jsx', '.jsx', 'x = <p><!-- \\u0041 --></p>;', 'HTML comment markers in JSX text');
add('none-div-after-closing-brace-in-subst', '.js', 'x = `${ a } \\u0041`; y = 2 / 1;', 'a closing brace of a substitution, then text');


// --- CL-2 (verifier A-4): `<` that could open a type parameter list or a generic JSX element ---
const HITCALL = 'globalThis.__HIT=1';
const EXH = EX + '("' + HITCALL + '")'; // an escaped exec reached through a stub, setting the flag
add('ident-tsx-generic-jsx-element', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<string> items={["a"]} />;\n' + EV + ';', 'a generic JSX element: the type argument is not an element, so the escape after it is code');
add('ident-tsx-generic-jsx-element-nested', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<Array<string>> items={[]} />;\n' + EV + ';', 'nested type arguments in a JSX element');
add('ident-tsx-generic-jsx-element-fn-type', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<(a: number) => void> />;\n' + EV + ';', 'a function type with => among the type arguments');
add('ident-tsx-generic-jsx-element-children', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<string> items={[]}>t</Select>;\n' + EV + ';', 'a generic JSX element with children and a closing tag');
add('ident-tsx-generic-jsx-element-trailing-comma', '.tsx', 'type T = string;\nconst Foo = (p: any) => null;\nconst el = <Foo<T,> prop="x" />;\n' + EV + ';', 'a trailing comma in the type arguments');
add('ident-tsx-generic-jsx-element-two', '.tsx', 'const Foo = (p: any) => null;\nconst el = <Foo<string, number> prop="x" />;\n' + EV + ';', 'two type arguments');
add('ident-tsx-generic-jsx-element-member', '.tsx', 'const NS = { Foo: (p: any) => null };\nconst el = <NS.Foo<string> prop="x" />;\n' + EV + ';', 'a member tag name with type arguments');
// A union of many members is a valid type argument list, whatever its length. R3-SEC-A2: the first lexer gave
// up after 64 KiB and read the rest of the file as JSX text, so an escaped call after the list read clean.
const UNION = (members) => 'A|'.repeat(members) + 'A';
const LONGHEAD = (members) => 'type A = string;\nconst Select = (p: any) => null;\nconst el = <Select<' + UNION(members) + '> items={[]} />;\n';
add('ident-tsx-generic-jsx-element-union-66k', '.tsx', LONGHEAD(33000) + EV + ';', 'a type argument list a little over 64 KiB (the lexer\'s first bound): the escape after it is code');
add('ident-tsx-generic-jsx-element-union-80k', '.tsx', LONGHEAD(40000) + EV + ';', 'the verifier\'s R3-SEC-A2 shape: 40,000 union members, then an escaped call');
add('ident-tsx-generic-arrow-default', '.tsx', 'const f = <T = unknown>(x: T) => ' + EV + ';', 'a generic arrow function whose parameter has a default');
add('ident-tsx-generic-arrow-const', '.tsx', 'const f = <const T,>(x: T) => ' + EV + ';', 'a const type parameter');
add('ident-tsx-generic-arrow-const-extends', '.tsx', 'const f = <const T extends readonly unknown[]>(x: T) => ' + EV + ';', 'a const type parameter with a constraint');
add('ident-tsx-generic-arrow-two', '.tsx', 'const f = <T, U>(x: T, y: U) => ' + EV + ';', 'two type parameters');
add('ident-tsx-generic-arrow-extends-default', '.tsx', 'const f = <T extends object = {}>(x: T) => ' + EV + ';', 'a constraint and a default');
add('ident-tsx-generic-arrow-default-comma', '.tsx', 'const f = <T = unknown,>(x: T) => ' + EV + ';', 'a default and a trailing comma');
add('ident-tsx-generic-arrow-async', '.tsx', 'const f = async <T,>(x: T) => ' + EV + ';', 'an async generic arrow function');
add('ident-tsx-generic-arrow-newline', '.tsx', 'const f = <\n  T,\n>(x: T) =>\n  ' + EV + ';', 'a type parameter list over several lines');
add('ident-tsx-generic-arrow-comment', '.tsx', 'const f = < /* c */ T,>(x: T) => ' + EV + ';', 'a comment inside the type parameter list');
add('ident-tsx-generic-arrow-in-call', '.tsx', 'const g = (cb: any) => cb;\nconst f = g(<T,>(x: T) => ' + EV + ');', 'a generic arrow function as an argument');
add('ident-tsx-generic-arrow-in-array', '.tsx', 'const f = [<T,>(x: T) => ' + EV + '];', 'a generic arrow function in an array');
add('ident-tsx-generic-arrow-return', '.tsx', 'function make() { return <T,>(x: T) => ' + EV + '; }', 'a generic arrow function after return');
add('ident-tsx-generic-arrow-after-element', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<string> />;\nconst f = <T,>(x: T) => ' + EV + ';', 'a generic JSX element, then a generic arrow function');
add('ident-tsx-generic-arrow-then-element', '.tsx', 'const f = <T,>(x: T) => <div>{' + EV + '}</div>;', 'a generic arrow function that returns an element holding an escaped call');
add('ident-mts-generic-arrow', '.mts', 'const f = <T,>(x: T) => ' + EV + ';', 'a generic arrow function in a TypeScript module');
add('ident-cts-generic-arrow', '.cts', 'const f = <const T,>(x: T) => ' + EV + ';', 'a const type parameter in CommonJS TypeScript');
add('ident-ts-generic-arrow-default', '.ts', 'const f = <T = unknown>(x: T) => ' + EV + ';', 'a generic arrow function with a default in .ts');
add('ident-flow-generic-arrow', '.js', '// @flow\nconst run = <T>(host: T) => ' + EV + ';', 'a Flow generic arrow function (the runtime needs a Flow stripper)', undefined, true);
add('ident-flow-generic-arrow-bound', '.js', '// @flow\nconst run = <T: Object>(host: T) => ' + EV + ';', 'a Flow bounded type parameter', undefined, true);
add('ident-flow-generic-arrow-default', '.js', '// @flow\nconst run = <T = string>(host: T) => ' + EV + ';', 'a Flow type parameter with a default', undefined, true);
add('ident-flow-generic-arrow-variance', '.js', '// @flow\nconst run = <+T>(host: T) => ' + EV + ';', 'a Flow type parameter with a variance sigil', undefined, true);
add('ident-flow-generic-arrow-two', '.jsx', '// @flow\nconst run = <T, U>(a: T, b: U) => ' + EV + ';', 'two Flow type parameters in a .jsx file', undefined, true);
add('ident-flow-generic-arrow-mjs', '.mjs', '// @flow\nexport const run = <T>(host: T) => ' + EV + ';', 'a Flow generic arrow function in a module', undefined, true);
add('none-tsx-generic-jsx-element-string-arg', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<"a>b"> items={[]} />;\nconst s = "' + U41 + '";', 'a string literal type holding > among the type arguments, then a string with an escape');
add('none-tsx-generic-jsx-element-text', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<string>>' + U41 + ' text</Select>;', 'JSX text under a generic element holds an escape: text, not code');
add('none-tsx-generic-jsx-element-regex-after', '.tsx', 'const Select = (p: any) => null;\nconst el = <Select<string> />;\nconst re = /[' + U41 + ']/;', 'a regular expression after a generic JSX element');
add('none-tsx-generic-jsx-element-union-80k', '.tsx', LONGHEAD(40000) + 'const s = "' + U41 + '";', 'the same long list, then an escape only in a string: read to its end, so clean');
add('none-tsx-generic-arrow-string-after', '.tsx', 'const f = <T,>(x: T) => x;\nconst s = "' + U41 + '";\nconst re = /' + U41 + '/;', 'a generic arrow function, then a string and a regex that hold escapes');
add('none-tsx-generic-arrow-body-template', '.tsx', 'const f = <T extends string>(x: T) => `' + U41 + ' ${x}`;', 'template text in the body of a generic arrow function');
add('none-tsx-generic-arrow-jsx-body', '.tsx', 'const f = <T,>(x: T) => <b>' + U41 + '</b>;', 'JSX text in the body of a generic arrow function');
add('none-ts-generic-call', '.ts', 'declare function f<T>(x: T): T;\nconst y = f<string>("' + U41 + '");', 'a generic call with a string argument');
add('none-tsx-jsx-with-paren-text', '.tsx', 'const el = <b>(plain)</b>;\nconst s = "' + U41 + '";', 'JSX text that starts with a parenthesis, then a string with an escape');
add('doubt-tsx-jsx-text-after-paren', '.tsx', 'const el = <Foo>(' + U41 + ' text)</Foo>;', 'JSX text that starts with a parenthesis could be a generic arrow function: the escape in the text is not code', { expect: true, reason: 'after <Foo> and a parenthesis the text could be the start of a generic arrow function: both readings are explored and the operator reading reaches the escape' });

function nodeRuns(v) {
  if (!['.js', '.cjs', '.es6'].includes(v.ext.toLowerCase())) return undefined;
  if (!v.text.includes('__HIT') && !v.text.includes('\\u0065val')) return undefined;
  try {
    const ctx = vm.createContext({ x: 1, y: 'A', a: 1, module: { exports: {} } });
    ctx.globalThis = ctx;
    ctx.window = ctx;
    new vm.Script(v.text).runInContext(ctx, { timeout: 1000 });
    return ctx.__HIT === 1;
  } catch (e) {
    return e instanceof SyntaxError ? null : false;
  }
}

function nodeRunsTs(v) {
  // A TypeScript vector that holds a payload: transpile the way tsc does, then run it in a fresh context.
  const ext = v.ext.toLowerCase();
  if (!['.ts', '.tsx', '.mts', '.cts'].includes(ext) || !v.text.includes('__HIT')) return undefined;
  try {
    const js = ts.transpileModule(v.text, { fileName: 'f' + ext, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.React, jsxFactory: 'h' } }).outputText;
    const ctx = vm.createContext({ h() {}, exports: {}, module: { exports: {} }, console });
    ctx.globalThis = ctx;
    // The arrow functions of the vectors are only defined; call them the way a caller would.
    const call = '\n;try { if (typeof f === "function") f(1); else if (Array.isArray(f)) f[0](1); } catch (e) {}\ntry { if (typeof make === "function") make()(1); } catch (e) {}\n';
    new vm.Script(js + call).runInContext(ctx, { timeout: 1000 });
    return ctx.__HIT === 1;
  } catch (e) {
    return e instanceof SyntaxError ? null : false;
  }
}

const out = {
  schema: 1,
  about: 'Vectors for scope.JSIdentifierEscape and scope_evidence.js_identifier_escape (R6-E7a). Generated by gen_jsescape_vectors.mjs; never edited by hand.',
  oracle: { name: 'typescript', version: ts.version, babel: require(babelPath + '/package.json').version, node: process.version, definition: 'a leaf token of ts.createSourceFile other than a string, template part, regular-expression literal or JSX text whose text holds a backslash' },
  vectors: [],
};
const ids = new Set();
for (const v of V) {
  if (ids.has(v.id)) throw new Error('duplicate id ' + v.id);
  ids.add(v.id);
  const hits = v.flow ? babelHits(v.text) : oracle(v.text, v.ext.toLowerCase());
  const o = hits.length > 0;
  const row = { id: v.id, ext: v.ext, text: v.text, note: v.note, oracle: o, oracle_offset: o ? hits[0] : -1 };
  if (v.flow) row.oracle_source = 'babel-flow';
  const run = v.flow ? undefined : (nodeRuns(v) ?? nodeRunsTs(v));
  if (run !== undefined) row.node_runs = run;
  if (v.deviation) {
    if (v.deviation.expect === o) throw new Error(`${v.id}: a deviation that agrees with the oracle`);
    row.expect = v.deviation.expect;
    row.deviation = v.deviation.reason;
  } else {
    row.expect = o;
  }
  // Naming discipline: ident-* vectors are escapes in code, none-* are not.
  if (v.id.startsWith('ident-') && !row.expect) throw new Error(`${v.id}: named ident but expect is false (oracle ${o})`);
  if (v.id.startsWith('none-') && row.expect) throw new Error(`${v.id}: named none but expect is true (oracle ${o}, offset ${hits[0]})`);
  out.vectors.push(row);
}
const dest = path.join(process.argv[2] || here, 'jsescape_vectors.json');
fs.writeFileSync(dest, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${out.vectors.length} vectors to ${dest}`);
