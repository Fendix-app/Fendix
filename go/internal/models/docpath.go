package models

import (
	"path"
	"regexp"
	"strings"
)

// IsDocPath reports whether a finding endpoint points at DOCUMENTATION: a file
// whose job is to be read by a person, where a credential is far more often a
// sample than a secret (RC-10b).
//
// It is decided by the FILE, never by a directory name alone. A directory called
// docs/ holds prose, but it also holds what ships with it: a Nacos
// configuration (docs/nacos/application.yaml, docs/nacos/config.properties), a
// docker-compose file, a deploy script, a runnable example. Those are
// deployable, and a credential in them is as real as one anywhere else, so a
// file is documentation only when its OWN form says so:
//
//   - prose markup (.md .mdx .markdown .adoc .asciidoc .rst), wherever it sits;
//   - a .txt file under a docs directory or named like a doc (README, NOTES,
//     CHANGELOG, ...), unless its name announces what it holds
//     (credentials.txt, passwords.txt, secrets.txt, api_key.txt): that is a
//     credential file with a text extension, not documentation;
//   - a file with no extension named like a doc (README, CHANGELOG, LICENSE),
//     or any other extension-less file under a docs directory except a build or
//     deploy file (Makefile, Dockerfile, ...);
//   - an HTML page under a docs directory that is not inside a served root
//     (public/, static/, templates/, www/, dist/, build/, ...): a page that is
//     served exposes what it holds, which is the opposite of a sample.
//
// Before any of that, three things are never documentation, whatever the
// extension or the directory says (CL-1 B-3):
//
//   - anything under bin/, sbin/, scripts/ or script/: it is there to run;
//   - anything whose name or directory announces credentials or configuration
//     (credentials, secrets, tokens, kubeconfig, .netrc, id_rsa, .env*, *.pem,
//     a config/ or settings/ directory, an extension-less config or settings
//     file): it is deployable, and a credential in it is real;
//   - a file whose first line is a "#!" interpreter line. A path cannot say
//     that, so the secrets scanner marks the evidence (NotDocumentation) and the
//     provenance index applies it.
//
// An extension-less file is documentation only when its name is a canonical
// document name (README, CHANGELOG, INSTALL, NOTICE, ...) or it sits under a
// docs directory and is not a build, deploy or run file by name.
//
// Anything else is not documentation, including every deployable or runnable
// format under docs/ (.yaml .yml .properties .toml .ini .cfg .conf .json .xml
// .sh .sql .py .js ...). The test is positive on purpose: a file the rule does
// not recognise keeps the weight it always had, so a misclassification can only
// leave a documentation sample at BLOCK, never hide a real credential.
//
// URL-shaped endpoints are never documentation (a route is a deployed surface),
// and the answer is a pure function of the endpoint (Constitution Rule 8).
func IsDocPath(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	ep := strings.ReplaceAll(endpoint, "\\", "/")
	if docEndpointIsURL(ep) {
		return false
	}
	// Strip a trailing ":<line>" suffix (IsTestPath does the same).
	if i := strings.LastIndex(ep, ":"); i > 0 {
		ep = ep[:i]
	}
	low := strings.ToLower(ep)
	base := path.Base(low)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	inDocs := docDirRe.MatchString(low)

	// A script, or a file that holds credentials or configuration, is never
	// documentation: the form below is only consulted for files that pass.
	if docScriptDirRe.MatchString(low) || docSensitiveDirRe.MatchString(low) ||
		docCredentialNameRe.MatchString(stem) || docCredentialFileRe.MatchString(base) ||
		(ext == "" && docConfigNameRe.MatchString(stem)) {
		return false
	}

	switch ext {
	case ".md", ".mdx", ".markdown", ".adoc", ".asciidoc", ".rst":
		return true
	case ".txt":
		return inDocs || docNameRe.MatchString(stem)
	case "":
		if docNameRe.MatchString(stem) {
			return true
		}
		return inDocs && !docDeployNames[stem]
	case ".html", ".htm":
		return inDocs && !docServedDirRe.MatchString(low)
	}
	return false
}

var (
	// docDirRe: a docs directory anywhere in the path.
	docDirRe = regexp.MustCompile(`(^|/)(docs?|documentation)(/|$)`)
	// docServedDirRe: a root whose files are served to a browser.
	docServedDirRe = regexp.MustCompile(`(^|/)(public|static|templates|www|wwwroot|webroot|dist|build|out|_site|assets|views)(/|$)`)
	// docNameRe: the base names (without extension) that are documentation.
	docNameRe = regexp.MustCompile(`^(readme|changelog|changes|history|contributing|authors|maintainers|notes|notice|license|copying|install|upgrading|todo|news|faq|thanks)$`)
	// docScriptDirRe: a directory that holds what runs. Matched on the whole
	// path, so a file that is itself called bin or scripts is covered too.
	docScriptDirRe = regexp.MustCompile(`(^|/)(bin|sbin|scripts?)(/|$)`)
	// docSensitiveDirRe: a directory that holds credentials or configuration,
	// including the dot-directories tools keep them in.
	docSensitiveDirRe = regexp.MustCompile(`(^|/)(credentials?|creds?|secrets?|tokens?|private|config|settings|\.aws|\.kube|\.ssh|\.gnupg|\.docker|\.gcloud|\.azure)(/|$)`)
	// docCredentialFileRe: whole file names that are credential or
	// configuration files in every tool's convention, with or without extension
	// (.env, .env.production, .netrc, id_rsa, kubeconfig, htpasswd, pgpass).
	docCredentialFileRe = regexp.MustCompile(`^(\.env.*|\.?netrc|\.?pgpass|\.?htpasswd|\.?npmrc|\.?pypirc|\.git-credentials|kubeconfig|id_[a-z0-9]+(\.pub)?)$`)
	// docConfigNameRe: an extension-less file named config or settings IS the
	// configuration (a kube or git config), not a page about it; with a prose
	// extension it is a page, and stays documentation.
	docConfigNameRe = regexp.MustCompile(`^(\.?config|\.?settings)$`)
	// docCredentialNameRe: a name that says the file holds credentials.
	docCredentialNameRe = regexp.MustCompile(`(credential|creds?\b|secret|passw|token|api[-_]?key|apikey|private|(^|[-_.])auth([-_.]|$)|id_rsa|\bkeys?\b)`)
)

// docDeployNames are extension-less files that build or deploy something.
var docDeployNames = map[string]bool{
	"makefile": true, "dockerfile": true, "vagrantfile": true, "jenkinsfile": true, "procfile": true,
	"rakefile": true, "gemfile": true, "brewfile": true, "pipfile": true, "caddyfile": true, "justfile": true,
	// What runs when called, by name: an extension-less file that is not a
	// document under docs/ and whose name is a verb.
	"entrypoint": true, "docker-entrypoint": true, "run": true, "start": true, "stop": true, "setup": true,
	"deploy": true, "bootstrap": true, "configure": true, "build": true, "launch": true, "boot": true,
	"init": true, "entry": true, "startup": true,
}

// docEndpointIsURL reports whether an endpoint is a live HTTP route rather than
// a source location ("GET /users", "/path", "https://host/path").
func docEndpointIsURL(ep string) bool {
	ep = strings.TrimSpace(ep)
	if i := strings.IndexByte(ep, ' '); i > 0 && i <= 7 && ep[0] >= 'A' && ep[0] <= 'Z' {
		ep = strings.TrimSpace(ep[i+1:])
	}
	return strings.HasPrefix(ep, "/") || strings.Contains(ep, "://")
}
