package secrets

import (
	"bytes"
	"crypto/rand"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"strings"
	"testing"
)

// Verification pass 1 (DE5-04, redteam5-09): the opaque-binary exemption for
// pictures and fonts rests on their structure, not on a header anyone can type.
// A genuine picture whose pixels are random (so entropy alone cannot clear it)
// stays complete; the same magic bytes in front of an undecodable stream do not.

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

func TestSearchValues_RealPicturesStayCompleteAndForgedHeadersDoNot(t *testing.T) {
	noise := make([]byte, 6000)
	if _, err := io.ReadFull(rand.Reader, noise); err != nil {
		t.Fatal(err)
	}
	// Magic bytes (and, for PNG, a plausible-looking first chunk) over an
	// undecodable stream.
	forged := map[string][]byte{
		"forged.png":   append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), noise...),
		"forged.gif":   append([]byte("GIF89a"), noise...),
		"forged.jpg":   append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, noise...),
		"forged.webp":  append([]byte("RIFF\x00\x10\x00\x00WEBPVP8 "), noise...),
		"forged.woff":  append([]byte("wOFF\x00\x01\x00\x00"), noise...),
		"forged.ttf":   append([]byte("true"), noise...),
		"forged.otf":   append([]byte("OTTO"), noise...),
		"forged.mp3":   append([]byte("ID3"), noise...),
		"forged.ogg":   append([]byte("OggS"), noise...),
		"forged.flac":  append([]byte("fLaC"), noise...),
		"forged.mp4":   append([]byte("\x00\x00\x00\x18ftypisom"), noise...),
		"forged.ico":   append([]byte{0, 0, 1, 0, 1, 0}, noise...),
		"forged-gif-c": append([]byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\xfe\xff"), noise...), // a "comment" holding a stream
	}
	for name, content := range forged {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, string(content))
			if res := search(t, root, searchPW); res.Complete() {
				t.Errorf("an undecodable stream behind the header of %s reads as fully searched", name)
			}
		})
	}
	for name, content := range realMedia(t) {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, string(content))
			if res := search(t, root, searchPW); !res.Complete() {
				t.Errorf("a genuine %s is reported as unread: %s", name, res.Coverage.LostDetail(240))
			}
		})
	}
}

// DE5-05: the reason a file is lost reads as a sentence for the customer, not as
// "binary?content?that?is?compressed?or?encrypted".
func TestSearchValues_TheLostReasonKeepsItsSpaces(t *testing.T) {
	noise := make([]byte, 6000)
	if _, err := io.ReadFull(rand.Reader, noise); err != nil {
		t.Fatal(err)
	}
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
