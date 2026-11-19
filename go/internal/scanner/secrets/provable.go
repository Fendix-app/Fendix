package secrets

import (
	"bufio"
	"context"
	"encoding/base64"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ── Credentials provable offline (RC-10b) ──────────────────────────────────
//
// A credential in documentation earns no deterministic-detection weight, unless
// it can be shown real from the bytes of the file alone, with no call to the
// provider:
//
//   - a GitHub token whose checksum is valid (the last 6 characters are the
//     base-62 CRC-32 of the 30 before them; a made-up token fails it 1 time in
//     56 billion);
//   - a private key whose PEM body base64-decodes to one well-formed DER
//     SEQUENCE (a made-up or elided key does not);
//   - an AWS access key id with its 40-character secret beside it (within three
//     lines), neither looking synthetic.
//
// Such a value keeps BLOCK in documentation (evidence.Evidence.OfflineProvable).
// It is computed only for files models.IsDocPath names, the one place the policy
// reads it.

var githubTokenRE = regexp.MustCompile(`^gh[opusr]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})$`)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base62Checksum(n uint32) string {
	var b [6]byte
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = base62[n%62]
		n /= 62
	}
	return string(b[:])
}

// githubChecksumValid reports whether tok is a GitHub token of the documented
// format whose checksum holds, and whose value does not look synthetic.
func githubChecksumValid(tok string) bool {
	m := githubTokenRE.FindStringSubmatch(tok)
	return m != nil && base62Checksum(crc32.ChecksumIEEE([]byte(m[1]))) == m[2] && !looksSampleLike(tok)
}

// derWellFormed reports whether b is exactly one DER SEQUENCE with a consistent
// length and a plausible minimum size.
func derWellFormed(b []byte) bool {
	if len(b) < 32 || b[0] != 0x30 {
		return false
	}
	l := int(b[1])
	if l < 0x80 {
		return 2+l == len(b)
	}
	n := l & 0x7f
	if n == 0 || n > 4 || len(b) < 2+n {
		return false
	}
	v := 0
	for _, x := range b[2 : 2+n] {
		v = v<<8 | int(x)
	}
	return 2+n+v == len(b)
}

var pemHeaderRE = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)

// pemBodyParses reports whether the PEM block whose header is on lines[idx]
// (0-based) has a base64 body that decodes to one well-formed DER SEQUENCE. The
// body is either the lines after the header up to the END line, or, in a JSON
// service-account file, the `\n`-escaped rest of the header's own line.
func pemBodyParses(lines []string, idx int) bool {
	line := lines[idx]
	loc := pemHeaderRE.FindStringIndex(line)
	if loc == nil {
		return false
	}
	rest := line[loc[1]:]
	var body []string
	if strings.TrimSpace(rest) != "" && (strings.Contains(rest, `\n`) || strings.Contains(rest, "END")) {
		t := strings.SplitN(rest, "-----END", 2)[0]
		for _, x := range strings.Split(strings.ReplaceAll(t, `\r`, ""), `\n`) {
			if strings.TrimSpace(x) != "" {
				body = append(body, x)
			}
		}
	} else {
		for j := idx + 1; j < len(lines) && j < idx+provableWindowAfter; j++ {
			t := strings.TrimSpace(lines[j])
			if strings.HasPrefix(t, "-----END") {
				break
			}
			body = append(body, t)
		}
	}
	var sb strings.Builder
	for _, x := range body {
		if strings.HasPrefix(x, "Proc-Type") || strings.HasPrefix(x, "DEK-Info") {
			continue
		}
		sb.WriteString(x)
	}
	raw, err := base64.StdEncoding.DecodeString(sb.String())
	return err == nil && derWellFormed(raw)
}

// patternByID returns the compiled regex of a registry rule.
func patternByID(id string) *regexp.Regexp {
	for i := range patterns {
		if patterns[i].id == id {
			return patterns[i].regex
		}
	}
	return nil
}

// lastGroup is the credential material of a match: its last participating group.
func lastGroup(m []string) string {
	for i := len(m) - 1; i >= 1; i-- {
		if m[i] != "" {
			return m[i]
		}
	}
	return m[0]
}

// awsPairProvable reports whether the AWS finding on lines[idx] (rule id) has its
// partner credential within three lines and neither value looks synthetic.
func awsPairProvable(lines []string, idx int, id string) bool {
	own := patternByID(id)
	if own == nil {
		return false
	}
	m := own.FindStringSubmatch(lines[idx])
	if m == nil || looksSampleLike(lastGroup(m)) {
		return false
	}
	other := patternByID("AWS_SECRET_KEY")
	if id == "AWS_SECRET_KEY" {
		other = patternByID("AWS_ACCESS_KEY")
	}
	if other == nil {
		return false
	}
	for j := idx - provableWindowBefore; j <= idx+provableWindowBefore; j++ {
		if j < 0 || j >= len(lines) || j == idx {
			continue
		}
		if om := other.FindStringSubmatch(lines[j]); om != nil && !looksSampleLike(lastGroup(om)) {
			return true
		}
	}
	return false
}

const (
	// provableWindowBefore is how far an AWS key's partner may sit from it, in lines.
	provableWindowBefore = 3
	// provableWindowAfter is how many lines after a PEM header its body may span.
	provableWindowAfter = 80
	// provableMaxCandidates bounds the documentation findings examined per file.
	provableMaxCandidates = 256
	// provableMaxLineBytes bounds a line kept for the examination.
	provableMaxLineBytes = 16 << 10
)

// markProvableInDoc sets OfflineProvable on the private-key and AWS findings of
// one documentation file whose value can be shown real from the file alone. The
// file is read a second time through root, by the same hardened open as the
// scan, keeping only the lines near a candidate. A file that cannot be read the
// second time leaves its findings unmarked: they are reported at WARN, never
// dropped.
func markProvableInDoc(ctx context.Context, root *os.Root, rel string, info fs.FileInfo, name string, out []emitted) []emitted {
	type cand struct {
		i    int // index in out
		line int // 1-based
	}
	var cands []cand
	for i := range out {
		switch out[i].ev.RuleID {
		case "secrets/PRIVATE_KEY", "secrets/AWS_ACCESS_KEY", "secrets/AWS_SECRET_KEY":
			k := strings.LastIndex(out[i].ev.Endpoint, ":")
			if k < 0 {
				continue
			}
			if n, err := strconv.Atoi(out[i].ev.Endpoint[k+1:]); err == nil && n >= 1 {
				cands = append(cands, cand{i, n})
			}
		}
		if len(cands) >= provableMaxCandidates {
			break
		}
	}
	if len(cands) == 0 {
		return out
	}
	need := map[int]bool{}
	for _, c := range cands {
		for n := c.line - provableWindowBefore; n <= c.line+provableWindowAfter; n++ {
			if n >= 1 {
				need[n] = true
			}
		}
	}
	f, err := openRegularFile(root, rel, info)
	if err != nil {
		return out
	}
	defer f.Close()
	src, _, err := textReaderPy(&io.LimitedReader{R: f, N: maxFileBytes + 1}, name)
	if err != nil {
		return out
	}
	kept := map[int]string{}
	last := 0
	br := bufio.NewReaderSize(src, 64<<10)
	for n := 1; ; n++ {
		if n&0xff == 0 && ctx.Err() != nil {
			return out
		}
		line, rerr := readCappedLine(br, provableMaxLineBytes)
		if need[n] {
			kept[n] = line
			last = n
		}
		if rerr != nil {
			break
		}
	}
	lines := make([]string, last)
	for n := 1; n <= last; n++ {
		lines[n-1] = kept[n]
	}
	for _, c := range cands {
		if c.line > len(lines) {
			continue
		}
		idx := c.line - 1
		switch out[c.i].ev.RuleID {
		case "secrets/PRIVATE_KEY":
			if pemBodyParses(lines, idx) {
				out[c.i].ev.OfflineProvable = true
			}
		case "secrets/AWS_ACCESS_KEY":
			if awsPairProvable(lines, idx, "AWS_ACCESS_KEY") {
				out[c.i].ev.OfflineProvable = true
			}
		case "secrets/AWS_SECRET_KEY":
			if awsPairProvable(lines, idx, "AWS_SECRET_KEY") {
				out[c.i].ev.OfflineProvable = true
			}
		}
	}
	return out
}

// readCappedLine reads one line, keeping at most max bytes of it and discarding
// the rest. The error is io.EOF after the last line.
func readCappedLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		chunk, isPrefix, err := br.ReadLine()
		if sb.Len() < max {
			room := max - sb.Len()
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			sb.Write(chunk)
		}
		if err != nil || !isPrefix {
			return sb.String(), err
		}
	}
}
