package scope

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Directories (decision D6'). A directory is left out of an analyzer's scope
// only when the directory itself holds the evidence that a tool, not a person,
// wrote it: an installed-package tree, a virtualenv, a build-output tree. A
// directory that is merely called node_modules, vendor, dist, build or target
// is in scope; its files are then classified one by one (ClassifyFile).
//
// ClassifyDir reads a handful of marker files in the directory and never walks
// below it. Its cost is one failed open per directory for the markers every
// directory is checked for, and a few more for a directory with a candidate
// name.

func isFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// smallFile reads at most n bytes of a regular file, or nil.
func smallFile(p string, n int) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return readHead(f, n)
}

var (
	reVenvCfg   = regexp.MustCompile(`(?mi)^\s*home\s*=`)
	reModules   = regexp.MustCompile(`(?m)^# \S+ v?\d\S*`)
	reCargoSig  = regexp.MustCompile(`^Signature: 8a477f597d28d172789f06886806bc55`)
	rePnpmMod   = regexp.MustCompile(`(?m)^layoutVersion:`)
	reNPMHidden = regexp.MustCompile(`"lockfileVersion"`)
)

func hasJSONKey(data []byte, keys ...string) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return false
	}
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return false
		}
	}
	return true
}

// ClassifyDir classifies the directory at abs (rel is its path relative to the
// scan root, forward slashes). It returns the zero Verdict when the directory
// holds no evidence of being installed or built output.
func ClassifyDir(abs, rel string) Verdict {
	rel = strings.ReplaceAll(rel, `\`, "/")
	base := path.Base(rel)
	parent := filepath.Dir(abs)

	// Any directory that is a Python virtual environment, whatever it is called.
	if cfg := smallFile(filepath.Join(abs, "pyvenv.cfg"), 4096); cfg != nil && reVenvCfg.Match(cfg) {
		return Verdict{ReasonPythonVenv}
	}
	if isFile(filepath.Join(abs, "conda-meta", "history")) {
		return Verdict{ReasonPythonVenv}
	}

	switch base {
	case "node_modules":
		if data := smallFile(filepath.Join(abs, ".package-lock.json"), 4096); data != nil && reNPMHidden.Match(data) {
			return Verdict{ReasonNPMInstall}
		}
		if isFile(filepath.Join(abs, ".yarn-integrity")) {
			return Verdict{ReasonNPMInstall}
		}
		if data := smallFile(filepath.Join(abs, ".modules.yaml"), 4096); data != nil && rePnpmMod.Match(data) {
			return Verdict{ReasonNPMInstall}
		}
	case "vendor":
		if data := smallFile(filepath.Join(abs, "modules.txt"), 8192); data != nil && reModules.Match(data) {
			return Verdict{ReasonGoVendor}
		}
		if data := smallFile(filepath.Join(abs, "composer", "installed.json"), 1<<20); data != nil &&
			isFile(filepath.Join(abs, "autoload.php")) && (hasJSONKey(data, "packages") || (len(data) > 0 && data[0] == '[')) {
			return Verdict{ReasonComposer}
		}
	case "target":
		if data := smallFile(filepath.Join(abs, "CACHEDIR.TAG"), 256); data != nil && reCargoSig.Match(data) {
			return Verdict{ReasonCargoTarget}
		}
		if isFile(filepath.Join(parent, "pom.xml")) &&
			(isDir(filepath.Join(abs, "maven-status")) || isDir(filepath.Join(abs, "maven-archiver")) || isDir(filepath.Join(abs, "surefire-reports"))) {
			return Verdict{ReasonMavenTarget}
		}
	case "build":
		for _, script := range []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
			if isFile(filepath.Join(parent, script)) {
				for _, sub := range []string{"classes", "libs", "tmp", "reports", "generated", "intermediates", "kotlin"} {
					if isDir(filepath.Join(abs, sub)) {
						return Verdict{ReasonGradleBuild}
					}
				}
				break
			}
		}
		if (isFile(filepath.Join(parent, "setup.py")) || isFile(filepath.Join(parent, "pyproject.toml"))) && isDir(filepath.Join(abs, "lib")) {
			if entries, err := os.ReadDir(abs); err == nil {
				for _, e := range entries {
					if e.IsDir() && (strings.HasPrefix(e.Name(), "bdist.") || strings.HasPrefix(e.Name(), "temp.")) {
						return Verdict{ReasonSetuptools}
					}
				}
			}
		}
	case ".next":
		if isFile(filepath.Join(abs, "BUILD_ID")) && isFile(filepath.Join(abs, "build-manifest.json")) {
			return Verdict{ReasonNextBuild}
		}
	case ".npm":
		if isDir(filepath.Join(abs, "_cacache")) {
			return Verdict{ReasonNPMCache}
		}
	case "site-packages", "dist-packages":
		if entries, err := os.ReadDir(abs); err == nil {
			for _, e := range entries {
				if e.IsDir() && strings.HasSuffix(e.Name(), ".dist-info") &&
					isFile(filepath.Join(abs, e.Name(), "RECORD")) && isFile(filepath.Join(abs, e.Name(), "METADATA")) {
					return Verdict{ReasonPythonInstall}
				}
			}
		}
	}

	// A package that npm installed: <...>/node_modules/<pkg> or
	// <...>/node_modules/@scope/<pkg>, whose package.json names exactly that
	// package and carries a version.
	if v := npmPackage(abs, rel); !v.None() {
		return v
	}
	return Verdict{}
}

// npmPackage classifies <...>/node_modules/<pkg> and
// <...>/node_modules/@scope/<pkg> by its package.json.
func npmPackage(abs, rel string) Verdict {
	parts := strings.Split(rel, "/")
	n := len(parts)
	var want string
	switch {
	case n >= 2 && parts[n-2] == "node_modules" && !strings.HasPrefix(parts[n-1], "@") && !strings.HasPrefix(parts[n-1], "."):
		want = parts[n-1]
	case n >= 3 && parts[n-3] == "node_modules" && strings.HasPrefix(parts[n-2], "@"):
		want = parts[n-2] + "/" + parts[n-1]
	default:
		return Verdict{}
	}
	data := smallFile(filepath.Join(abs, "package.json"), 1<<20)
	if data == nil {
		return Verdict{}
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &pkg) != nil || pkg.Name != want || pkg.Version == "" {
		return Verdict{}
	}
	return Verdict{ReasonNPMInstall}
}
