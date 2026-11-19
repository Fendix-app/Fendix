package models

import "testing"

// IsDocPath decides documentation by the FILE, not by a directory name alone
// (RC-10b). The jeecg case: a Nacos configuration sits under docs/ and is
// deployable.
func TestIsDocPath(t *testing.T) {
	docs := []string{
		"README.md", "README.md:7", "docs/guide.md", "docs/guide.md:12", "docs/inline.md",
		"docs/ref.adoc", "docs/ref.rst", "guide/intro.mdx", "notes/design.markdown", "a/b/c/page.asciidoc",
		"docs/notes.txt", "docs/install.txt", "README.txt", "NOTES.txt", "CHANGELOG", "CHANGELOG.md", "LICENSE", "LICENSE.txt",
		"docs/README", "docs/page.html", "docs/api/index.html", "documentation/intro.htm",
		`docs\guide.md:3`, "Docs/Guide.MD", "a/DOCS/b.rst",
	}
	for _, p := range docs {
		if !IsDocPath(p) {
			t.Errorf("IsDocPath(%q) = false, want documentation", p)
		}
	}
	notDocs := []string{
		// The jeecg Nacos configuration and everything else deployable under docs/.
		"docs/nacos/application.yaml", "docs/nacos/application.yml", "docs/nacos/config.properties",
		"docs/deploy/docker-compose.yml", "docs/k8s/secret.yaml", "docs/config.toml", "docs/app.ini", "docs/app.cfg",
		"docs/app.conf", "docs/settings.json", "docs/data.xml", "docs/.env", "docs/deploy.sh", "docs/schema.sql",
		"docs/main.tf", "docs/Makefile", "docs/Dockerfile", "docs/Vagrantfile",
		// Code and examples, even under docs/.
		"docs/examples/app.py", "docs/examples/server.js", "docs/conf.py", "docs/src/Main.java",
		// A file named for what it holds is a credential file, not a document.
		"docs/credentials.txt", "credentials.txt", "passwords.txt", "docs/secrets.txt", "api_key.txt", "docs/tokens.txt",
		"private-key.txt", "id_rsa.txt", "keys.txt",
		// A .txt that is neither under docs/ nor named like a document.
		"requirements.txt", "data/list.txt", "out.txt",
		// Served pages expose what they hold.
		"public/index.html", "static/page.html", "templates/mail.html", "www/index.html", "dist/index.html", "docs/dist/index.html",
		"src/components/card.html", "index.html",
		// Source, tests, notebooks, templates.
		"src/config.py", "app.js", "tests/test_x.py", "notebooks/demo.ipynb", ".env.example", "config.yaml",
		// URL-shaped endpoints are routes, not files.
		"GET /docs", "/docs/guide.md", "https://example.test/README.md", "GET /README.md",
		"", ":3",
	}
	for _, p := range notDocs {
		if IsDocPath(p) {
			t.Errorf("IsDocPath(%q) = true, want NOT documentation", p)
		}
	}
}

// A docs directory alone never makes a file documentation: for every deployable
// or runnable extension, docs/ and src/ agree.
func TestIsDocPathDirectoryNameAloneIsNotEnough(t *testing.T) {
	for _, ext := range []string{".yaml", ".yml", ".properties", ".toml", ".ini", ".cfg", ".conf", ".json", ".xml", ".env",
		".sh", ".sql", ".tf", ".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".gradle", ".plist"} {
		if IsDocPath("docs/x" + ext) {
			t.Errorf("docs/x%s is documentation by directory name alone", ext)
		}
	}
}

// The classification is a pure function of the endpoint.
func TestIsDocPathIsDeterministic(t *testing.T) {
	for _, p := range []string{"README.md:1", "docs/nacos/application.yaml:3", "a/b.txt"} {
		first := IsDocPath(p)
		for i := 0; i < 50; i++ {
			if IsDocPath(p) != first {
				t.Fatalf("IsDocPath(%q) changed between calls", p)
			}
		}
	}
}

// CL-1 / B-3 (independent verification): scripts and credential-named files are not
// documentation, whatever their name or directory says.
func TestIsDocPathNeverScriptsOrCredentialFiles(t *testing.T) {
	notDocs := []string{
		// A script directory: nothing under it is documentation.
		"bin/install", "bin/README.md", "sbin/setup", "scripts/README.md", "scripts/install", "script/notes",
		"a/b/scripts/readme.md", "docs/scripts/guide.md", "docs/bin/run",
		// A file named for what it holds, in every doc form, extension-less included.
		"docs/aws/credentials", "docs/.aws/credentials", "docs/secrets", "docs/secrets.md", "docs/token", "docs/tokens.rst",
		"docs/kubeconfig", "docs/kube/config", "docs/id_rsa", "docs/.netrc", "docs/netrc", "docs/.env", "docs/.env.production",
		"docs/htpasswd", "docs/pgpass", "docs/server.pem",
		// A configuration directory: the file is deployable, not prose.
		"config/notes.txt", "config/install", "config/README.md", "settings/README.md", "docs/config/guide.md", "docs/settings/x.md",
		// An extension-less file under docs/ that runs something.
		"docs/entrypoint", "docs/run", "docs/start", "docs/deploy", "docs/setup", "docs/bootstrap",
		// An extension-less file that is not a canonical document name.
		"tools/run", "deploy/start", "run", "entrypoint",
	}
	for _, p := range notDocs {
		if IsDocPath(p) {
			t.Errorf("IsDocPath(%q) = true: a script or credential file is not documentation", p)
		}
	}
	docs := []string{
		"INSTALL", "docs/INSTALL", "NOTICE", "AUTHORS", "CONTRIBUTING", "LICENSE", "CHANGES", "HISTORY", "tools/history", "deploy/upgrading",
		"docs/README", "docs/guide", "docs/configuration/system.md", "docs/index.html", "README.md",
	}
	for _, p := range docs {
		if !IsDocPath(p) {
			t.Errorf("IsDocPath(%q) = false, want documentation (a canonical doc name, or prose under docs/)", p)
		}
	}
}
