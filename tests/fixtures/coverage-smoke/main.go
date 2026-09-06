package main

import (
	"fmt"

	"golang.org/x/text/language"
)

// ParseAcceptLanguage in golang.org/x/text < v0.3.7 is GO-2021-0113
// (CVE-2021-38561). The call is deliberate: govulncheck reports only
// vulnerabilities reachable from the code, so the network smoke needs a
// reachable one to prove module resolution AND detection end to end.
func main() {
	tags, _, err := language.ParseAcceptLanguage("en-US,en;q=0.9")
	fmt.Println(tags, err)
}
