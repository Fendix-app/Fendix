package secrets

import (
	"regexp"
	"strings"
)

// connectionStringSpans returns the credential spans of one
// DB_CONNECTION_STRING match (R-013).
//
// The rule's regex finds a connection string and marks where its password
// starts, but its capture stops at the first ; & ' " or whitespace (JDBC
// properties) or at the first @ (URL userinfo). All of those can occur inside
// a password, and redacting only the capture published the rest:
// `password={Pw;RestOfSecret9}` was evidence `password=[REDACTED len=3];RestOfSecret9}`.
// This function decides where the password ENDS, and errs towards redacting
// more: when the end is ambiguous, the extra text is redacted, never shown.
//
//   - URL userinfo (scheme://user:PASSWORD@host): the password runs to the
//     LAST @ of the authority, which ends at the first / ? # whitespace or
//     closing quote after the capture, as URL parsers split userinfo from the
//     host at the last @.
//   - JDBC property (password=PASSWORD): a value that starts with { is a SQL
//     Server braced value and runs to its closing } (}} is an escaped brace).
//     Any other value runs to the next ; or & (or &amp;) that starts another
//     key=value property, to the closing quote of the string literal it sits
//     in (a backslash escapes the next byte), or to whitespace that starts
//     another connection string; outside a literal, otherwise to the end of
//     the line. So an unencoded & or ; that does not start a property, a quote
//     of the other kind, a space inside a literal, $, @ and %-escapes are all
//     part of the password.
//   - Every further password= property of the same connection string is
//     returned as a span too: FindAll resumes after the first match and only
//     restarts at a new `jdbc:`, so a second password in one URL was never
//     matched and was published in full.
//
// The match itself, and so detection, is unchanged; only the redacted extent
// grows. The first span starts where the capture does, so the identifier and
// placeholder classification still see the value at the same place.
func connectionStringSpans(line string, sub []int) [][2]int {
	if len(sub) >= 4 && sub[2] >= 0 {
		start, end := sub[2], sub[3]
		end = userinfoPasswordEnd(line, end)
		return [][2]int{{start, end}}
	}
	if len(sub) < 6 || sub[4] < 0 {
		return nil
	}
	start := sub[4]
	quote := literalQuote(line, start)
	end := propertyValueEnd(line, start, quote)
	if end < sub[5] {
		end = sub[5]
	}
	spans := [][2]int{{start, end}}

	// Further password properties of the same connection string.
	stop := connectionStringEnd(line, end, quote)
	lower := strings.ToLower(line)
	for pos := end; pos < stop; {
		i := strings.Index(lower[pos:stop], "password=")
		if i < 0 {
			break
		}
		k := pos + i
		vs := k + len("password=")
		pos = vs
		if k == 0 || !strings.ContainsRune("?;&", rune(line[k-1])) {
			continue // `xpassword=`, or not a property boundary
		}
		if vs >= stop || strings.ContainsRune("$&;\"' \t", rune(line[vs])) {
			continue // empty, or an interpolation the rule does not report
		}
		ve := propertyValueEnd(line, vs, quote)
		if ve > stop {
			ve = stop
		}
		spans = append(spans, [2]int{vs, ve})
		pos = ve
	}
	return spans
}

// userinfoPasswordEnd extends a userinfo password whose capture ends at the
// first @ to the last @ of the authority.
func userinfoPasswordEnd(line string, end int) int {
	last := -1
	for i := end; i < len(line); i++ {
		c := line[i]
		if c == '/' || c == '?' || c == '#' || c == '"' || c == '\'' || c == ' ' || c == '\t' {
			break
		}
		if c == '@' {
			last = i
		}
	}
	if last > end {
		return last
	}
	return end
}

// literalQuote returns the quote byte of the string literal that encloses
// position pos on the line, or 0 when pos is outside any literal.
func literalQuote(line string, pos int) byte {
	if open := enclosingQuote(line[:pos]); open >= 0 {
		return line[open]
	}
	return 0
}

// propertyStartRE matches the start of a key=value property.
var propertyStartRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*=`)

// connStartRE matches the start of another connection string or URL.
var connStartRE = regexp.MustCompile(`(?i)^(?:jdbc:|[a-z][a-z0-9+.\-]*://)`)

// startsProperty reports whether the delimiter at i (; or &) begins another
// key=value property. `&amp;` counts as an XML-escaped &.
func startsProperty(line string, i int) bool {
	j := i + 1
	if line[i] == '&' && strings.HasPrefix(line[j:], "amp;") {
		j += len("amp;")
	}
	return propertyStartRE.MatchString(line[j:])
}

// startsConnectionString reports whether the whitespace run at i is followed
// by another connection string.
func startsConnectionString(line string, i int) bool {
	j := i
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		j++
	}
	return connStartRE.MatchString(line[j:])
}

// propertyValueEnd returns the end of the property value starting at vs.
func propertyValueEnd(line string, vs int, quote byte) int {
	if vs < len(line) && line[vs] == '{' {
		for i := vs + 1; i < len(line); i++ {
			if line[i] != '}' {
				continue
			}
			if i+1 < len(line) && line[i+1] == '}' {
				i++ // }} is an escaped brace inside the value
				continue
			}
			return i + 1
		}
		// Unterminated brace: fall through and redact to the plain end.
	}
	for i := vs; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == '\\':
			i++
		case quote != 0 && c == quote:
			return i
		case (c == ';' || c == '&') && startsProperty(line, i):
			return i
		case (c == ' ' || c == '\t') && startsConnectionString(line, i):
			return i
		}
	}
	return len(strings.TrimRight(line, " \t\r\n"))
}

// connectionStringEnd returns where the connection string holding position
// from ends: the closing quote of its literal, whitespace that starts another
// connection string, or the end of the line.
func connectionStringEnd(line string, from int, quote byte) int {
	for i := from; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == '\\':
			i++
		case quote != 0 && c == quote:
			return i
		case (c == ' ' || c == '\t') && startsConnectionString(line, i):
			return i
		}
	}
	return len(line)
}
