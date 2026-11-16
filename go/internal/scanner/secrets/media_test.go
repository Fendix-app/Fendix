package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	mrand "math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Verification pass 1 (DE5-04, redteam5-09): the opaque-binary exemption for
// pictures and fonts rests on their structure, not on a header anyone can type.
// Its crypto/rand version (TestSearchValues_RealPicturesStayCompleteAndForgedHeadersDoNot)
// was removed in Round 6 (review, OR-50): its noise made the 1.9 % mp4 flake
// (R5-12) unreproducible. The seeded tests below hold the same property over
// 1,000 runs and 64 fixed seeds, for every forged header and genuine picture.

func noiseImage(t *testing.T) image.Image {
	t.Helper()
	pix := make([]byte, 64*64*4)
	if _, err := io.ReadFull(rand.Reader, pix); err != nil {
		t.Fatal(err)
	}
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	copy(img.Pix, pix)
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	return img
}

// realMedia is kept for search_round5_test.go, which uses it.
func realMedia(t *testing.T) map[string][]byte {
	t.Helper()
	img := noiseImage(t)
	var p, g, j bytes.Buffer
	if err := png.Encode(&p, img); err != nil {
		t.Fatal(err)
	}
	pal := image.NewPaletted(image.Rect(0, 0, 64, 64), color.Palette{color.Black, color.White, color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}})
	noise := make([]byte, 64*64)
	_, _ = io.ReadFull(rand.Reader, noise)
	for i, b := range noise {
		pal.Pix[i] = b % 4
	}
	if err := gif.Encode(&g, pal, nil); err != nil {
		t.Fatal(err)
	}
	if err := jpeg.Encode(&j, img, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"real.png": p.Bytes(), "real.gif": g.Bytes(), "real.jpg": j.Bytes()}
}

// DE5-05: the reason a file is lost reads as a sentence for the customer, not as
// "binary?content?that?is?compressed?or?encrypted".
func TestSearchValues_TheLostReasonKeepsItsSpaces(t *testing.T) {
	noise := wse2Bytes(wse2RNG(0), 6000)
	root := t.TempDir()
	writeFile(t, root, "opaque.bin", string(noise))
	res := search(t, root, searchPW)
	detail := res.Coverage.LostDetail(400)
	if !strings.Contains(detail, "binary content that is compressed or encrypted and cannot be decoded") {
		t.Errorf("the reason is garbled or missing: %q", detail)
	}
	if strings.Contains(detail, "binary?content") {
		t.Errorf("the reason was run through the name sanitiser: %q", detail)
	}
}

// ---------------------------------------------------------------------------
// Round 6, WS-E2: R5-12 (and the R5-11 media neighbour).
//
// The test above draws its noise from crypto/rand, so a failure cannot be
// reproduced and a 1.9 % flake (sre5: 14 of 1,000 mp4 runs) passes CI most of
// the time. The defect behind the flake is real: validISOBMFF accepts the ftyp
// box plus any next box whose type bytes happen to be printable, and an
// attacker types those bytes on purpose. Here the noise is seeded: 64 fixed
// seeds, 1,000 runs, the same bytes on every machine, and the crafted header
// is a deterministic case of its own.

// wse2MediaSeeds are the 64 fixed seeds. Never change them: a new failure must
// reproduce from its seed and run index alone.
var wse2MediaSeeds = func() [64]uint64 {
	var s [64]uint64
	for i := range s {
		s[i] = 0x5eed0000 + uint64(i)*0x9e3779b97f4a7c15
	}
	return s
}()

// wse2MediaRuns is 1,000 (G2.x / EXECUTION-PLAN §5: "1,000/1,000 with 64 fixed
// seeds"). FENDIX_MEDIA_RUNS overrides it for a quick local loop.
func wse2MediaRuns(t *testing.T) int {
	if v := os.Getenv("FENDIX_MEDIA_RUNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("FENDIX_MEDIA_RUNS=%q", v)
		}
		return n
	}
	return 1000
}

func wse2RNG(run int) *mrand.Rand {
	return mrand.New(mrand.NewPCG(wse2MediaSeeds[run%len(wse2MediaSeeds)], uint64(run)))
}

func wse2Bytes(rng *mrand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// wse2Forged is the forged-header set of the test above, over seeded noise.
func wse2Forged(noise []byte) map[string][]byte {
	cat := func(h string) []byte { return append([]byte(h), noise...) }
	return map[string][]byte{
		"forged.png":   cat("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
		"forged.gif":   cat("GIF89a"),
		"forged.jpg":   cat("\xFF\xD8\xFF\xE0"),
		"forged.webp":  cat("RIFF\x00\x10\x00\x00WEBPVP8 "),
		"forged.woff":  cat("wOFF\x00\x01\x00\x00"),
		"forged.ttf":   cat("true"),
		"forged.otf":   cat("OTTO"),
		"forged.mp3":   cat("ID3"),
		"forged.ogg":   cat("OggS"),
		"forged.flac":  cat("fLaC"),
		"forged.mp4":   cat("\x00\x00\x00\x18ftypisom"),
		"forged.ico":   cat("\x00\x00\x01\x00\x01\x00"),
		"forged-gif-c": cat("GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\xfe\xff"),
	}
}

// validISOBMFF over 1,000 seeded runs: an ftyp box followed by noise is never
// media. (Unit level, for the mp4 judgement only; the end-to-end test below
// holds every format. At this level validGIF also accepts the forged GIF
// headers over noise, but the search catches the comment form by other means.)
// A failure names its seed index and run, so it reproduces exactly.
func TestKnownMedia_R5_12_SeededForgedMP4IsNeverMedia(t *testing.T) {
	runs := wse2MediaRuns(t)
	bad := 0
	var first []string
	for run := 0; run < runs; run++ {
		content := wse2Forged(wse2Bytes(wse2RNG(run), 6000))["forged.mp4"]
		if knownMedia(content[:512], int64(len(content))) {
			bad++
			if len(first) < 5 {
				first = append(first, fmt.Sprintf("run %d seed[%d]", run, run%len(wse2MediaSeeds)))
			}
		}
	}
	if bad > 0 {
		t.Fatalf("validISOBMFF accepted an ftyp box over seeded noise in %d of %d runs (first: %v)", bad, runs, first)
	}
}

// The same property end to end: the value search never calls a forged file
// fully searched, over 1,000 seeded runs (the observable R5-12 flake), and a
// genuine picture of seeded pixels always is (next test).
func TestSearchValues_R5_12_SeededForgedHeadersNeverReadComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("13,000 searches (about 20 s); the mp4 and GIF judgements have their own tests")
	}
	runs := wse2MediaRuns(t)
	root := t.TempDir()
	fails := map[string]int{}
	var first []string
	for run := 0; run < runs; run++ {
		noise := wse2Bytes(wse2RNG(run), 6000)
		for name, content := range wse2Forged(noise) {
			path := root + "/" + name
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
			if search(t, root, searchPW).Complete() {
				fails[name]++
				if len(first) < 5 {
					first = append(first, fmt.Sprintf("%s run %d seed[%d]", name, run, run%len(wse2MediaSeeds)))
				}
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(fails) > 0 {
		t.Fatalf("forged headers over seeded noise read as fully searched in %v of %d runs (first: %v)", fails, runs, first)
	}
}

func TestSearchValues_R5_12_SeededRealPicturesStayComplete(t *testing.T) {
	// One genuine picture set per seed: real media must keep its exemption
	// whatever its pixels are (a fix for R5-12 must not make every repository
	// with pictures unknown).
	for i := range wse2MediaSeeds {
		rng := wse2RNG(i)
		img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
		copy(img.Pix, wse2Bytes(rng, len(img.Pix)))
		for k := 3; k < len(img.Pix); k += 4 {
			img.Pix[k] = 255
		}
		var p, j bytes.Buffer
		if err := png.Encode(&p, img); err != nil {
			t.Fatal(err)
		}
		if err := jpeg.Encode(&j, img, &jpeg.Options{Quality: 95}); err != nil {
			t.Fatal(err)
		}
		pal := image.NewPaletted(image.Rect(0, 0, 64, 64), color.Palette{color.Black, color.White, color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}})
		for k, b := range wse2Bytes(rng, len(pal.Pix)) {
			pal.Pix[k] = b % 4
		}
		var g bytes.Buffer
		if err := gif.Encode(&g, pal, nil); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string][]byte{"real.png": p.Bytes(), "real.gif": g.Bytes(), "real.jpg": j.Bytes()} {
			root := t.TempDir()
			writeFile(t, root, name, string(content))
			if res := search(t, root, searchPW); !res.Complete() {
				t.Errorf("seed[%d]: a genuine %s is reported as unread: %s", i, name, res.Coverage.LostDetail(240))
			}
		}
	}
}

// R5-12 as an attack, not a flake: the next box after ftyp is chosen by hand
// (a printable type, a sane size), and the payload is an undecodable stream.
func TestSearchValues_R5_12_CraftedMP4SecondBoxIsNotMedia(t *testing.T) {
	payload := wse2Bytes(wse2RNG(0), 6000)
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0x18})
	b.WriteString("ftypisom")
	b.Write([]byte{0, 0, 2, 0})
	b.WriteString("isomiso2")
	_ = binary.Write(&b, binary.BigEndian, uint32(8+len(payload)))
	b.WriteString("free")
	b.Write(payload)
	root := t.TempDir()
	writeFile(t, root, "clip.mp4", b.String())
	if res := search(t, root, searchPW); res.Complete() {
		t.Fatal("an mp4 whose second box was typed by hand over an undecodable stream reads as fully searched")
	}
}

// OR-14 (R5-11/R5-12 neighbour): a forged GIF header over seeded noise read as
// fully searched in 8 of 1,000 runs at checkpoint f438bc3 (first: run 94,
// seed[30]). validGIF walks the blocks inside the 512-byte sample and accepts
// when the noise happens to frame as blocks. Both forged GIF forms, every seeded
// run: never complete.
func TestSearchValues_OR14_SeededForgedGIFNeverReadsComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("2,000 searches (about 13 s)")
	}
	runs := wse2MediaRuns(t)
	root := t.TempDir()
	fails := map[string]int{}
	var first []string
	for run := 0; run < runs; run++ {
		forged := wse2Forged(wse2Bytes(wse2RNG(run), 6000))
		for _, name := range []string{"forged.gif", "forged-gif-c"} {
			path := root + "/" + name
			if err := os.WriteFile(path, forged[name], 0o644); err != nil {
				t.Fatal(err)
			}
			if search(t, root, searchPW).Complete() {
				fails[name]++
				if len(first) < 5 {
					first = append(first, fmt.Sprintf("%s run %d seed[%d]", name, run, run%len(wse2MediaSeeds)))
				}
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(fails) > 0 {
		t.Fatalf("a forged GIF over seeded noise read as fully searched in %v of %d runs (first: %v)", fails, runs, first)
	}
}

// Review (OR-50) control: a genuine ISO-BMFF file keeps the media exemption.
// ftyp, then moov holding an mvhd, then mdat whose payload is seeded noise (as
// compressed video is): every box size consistent and the boxes ending exactly
// at the end of the file. A fix for R5-12 must not make real video unknown.
func TestSearchValues_R5_12_RealMP4StaysComplete(t *testing.T) {
	box := func(typ string, body []byte) []byte {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint32(8+len(body)))
		b.WriteString(typ)
		b.Write(body)
		return b.Bytes()
	}
	ftyp := box("ftyp", []byte("isom\x00\x00\x02\x00isomiso2avc1mp41"))
	mvhd := make([]byte, 100)                         // version 0 mvhd body
	binary.BigEndian.PutUint32(mvhd[12:], 1000)       // timescale
	binary.BigEndian.PutUint32(mvhd[16:], 5000)       // duration
	binary.BigEndian.PutUint32(mvhd[20:], 0x00010000) // rate 1.0
	binary.BigEndian.PutUint16(mvhd[24:], 0x0100)     // volume 1.0
	binary.BigEndian.PutUint32(mvhd[96:], 2)          // next track id
	moov := box("moov", box("mvhd", mvhd))
	for i := range wse2MediaSeeds {
		file := append(append(append([]byte(nil), ftyp...), moov...), box("mdat", wse2Bytes(wse2RNG(i), 6000))...)
		root := t.TempDir()
		writeFile(t, root, "clip.mp4", string(file))
		if res := search(t, root, searchPW); !res.Complete() {
			t.Fatalf("seed[%d]: a genuine mp4 is reported as unread: %s", i, res.Coverage.LostDetail(240))
		}
	}
}
