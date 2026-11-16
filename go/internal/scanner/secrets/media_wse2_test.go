package secrets

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/gif"
	"testing"
)

// Round 6, WS-E2 (R5-12, OR-14): neighbours of the seeded media tests. What a
// stricter structural check must still call media, and what it must now refuse.

func wse2Box(typ string, body []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(8+len(body)))
	b.WriteString(typ)
	b.Write(body)
	return b.Bytes()
}

func wse2Cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestKnownMedia_WSE2_ISOBMFFFramings(t *testing.T) {
	ftyp := wse2Box("ftyp", []byte("isom\x00\x00\x02\x00isomiso2avc1mp41"))
	heic := wse2Box("ftyp", []byte("heic\x00\x00\x00\x00mif1heic"))
	noise := wse2Bytes(wse2RNG(3), 6000)
	zeros := make([]byte, 64)
	for name, tc := range map[string]struct {
		file []byte
		want bool
	}{
		"moov first, mdat of noise":              {wse2Cat(ftyp, wse2Box("moov", make([]byte, 120)), wse2Box("mdat", noise)), true},
		"free padding of zeros, then mdat":       {wse2Cat(ftyp, wse2Box("free", zeros), wse2Box("mdat", noise)), true},
		"empty free, mdat first, moov last":      {wse2Cat(ftyp, wse2Box("free", nil), wse2Box("mdat", noise), wse2Box("moov", make([]byte, 120))), true},
		"heic: meta then mdat":                   {wse2Cat(heic, wse2Box("meta", make([]byte, 200)), wse2Box("mdat", noise)), true},
		"free padding that holds a payload":      {wse2Cat(ftyp, wse2Box("free", noise), wse2Box("mdat", zeros)), false},
		"skip padding that holds a payload":      {wse2Cat(ftyp, wse2Box("skip", noise)), false},
		"a box type outside the top-level set":   {wse2Cat(ftyp, wse2Box("abcd", noise)), false},
		"a box that runs past the end of file":   {wse2Cat(ftyp, []byte{0x7f, 0xff, 0xff, 0xff}, []byte("mdat"), noise), false},
		"a box smaller than its header":          {wse2Cat(ftyp, []byte{0, 0, 0, 4}, []byte("mdat"), noise), false},
		"ftyp whose brand list is not brands":    {wse2Cat([]byte{0, 0, 0, 0x14}, []byte("ftypisom"), []byte{0, 0, 2, 0}, []byte{0xde, 0xad, 0xbe, 0xef}, wse2Box("mdat", noise)), false},
		"ftyp that is not a whole number of u32": {wse2Cat([]byte{0, 0, 0, 0x13}, []byte("ftypisom"), []byte{0, 0, 2, 0}, []byte("iso"), wse2Box("mdat", noise)), false},
	} {
		t.Run(name, func(t *testing.T) {
			head := tc.file[:min(len(tc.file), 4096)]
			if got := knownMedia(head, int64(len(tc.file))); got != tc.want {
				t.Errorf("knownMedia = %v, want %v", got, tc.want)
			}
		})
	}
}

// A fragmented MP4 starts with ftyp too (CMAF), so its moov, styp and moof
// framing is media.
func TestKnownMedia_WSE2_FragmentedMP4(t *testing.T) {
	ftyp := wse2Box("ftyp", []byte("iso6\x00\x00\x00\x00iso6cmfc"))
	file := wse2Cat(ftyp, wse2Box("moov", make([]byte, 120)), wse2Box("styp", []byte("msdh\x00\x00\x00\x00msdhmsix")), wse2Box("moof", make([]byte, 100)), wse2Box("mdat", wse2Bytes(wse2RNG(4), 4000)))
	if !knownMedia(file[:min(len(file), 4096)], int64(len(file))) {
		t.Error("a fragmented MP4's framing is not recognised")
	}
}

func wse2GenuineGIF(t *testing.T, frames int) []byte {
	t.Helper()
	pal := color.Palette{color.Black, color.White, color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}}
	anim := &gif.GIF{}
	for f := 0; f < frames; f++ {
		img := image.NewPaletted(image.Rect(0, 0, 32, 32), pal)
		for i, b := range wse2Bytes(wse2RNG(f), len(img.Pix)) {
			img.Pix[i] = b % 4
		}
		anim.Image = append(anim.Image, img)
		anim.Delay = append(anim.Delay, 10)
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, anim); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestKnownMedia_WSE2_GIFStructure(t *testing.T) {
	for _, frames := range []int{1, 3} {
		file := wse2GenuineGIF(t, frames)
		if !knownMedia(file, int64(len(file))) {
			t.Errorf("a genuine %d-frame GIF is not recognised", frames)
		}
		// Bytes after the trailer are a place to hide a payload when the length is known.
		if padded := append(append([]byte(nil), file...), 'x'); knownMedia(padded, int64(len(padded))) {
			t.Errorf("a %d-frame GIF with a byte after its trailer is recognised", frames)
		}
		// A comment of noise is a stream passed through a comment.
		bad := append([]byte(nil), file[:13+3*4]...) // header, screen, 4-colour table
		bad = append(bad, 0x21, 0xFE, 0xFF)
		bad = append(bad, wse2Bytes(wse2RNG(9), 255)...)
		bad = append(bad, 0)
		bad = append(bad, file[13+3*4:]...)
		if knownMedia(bad, int64(len(bad))) {
			t.Errorf("a %d-frame GIF with a noise comment is recognised", frames)
		}
	}
	file := wse2GenuineGIF(t, 1)
	zeroW := append([]byte(nil), file...)
	zeroW[6], zeroW[7] = 0, 0
	if knownMedia(zeroW, int64(len(zeroW))) {
		t.Error("a GIF with a zero-width screen is recognised")
	}
	reserved := append([]byte(nil), file...)
	if i := bytes.IndexByte(reserved[13:], 0x2C); i >= 0 {
		reserved[13+i+9] |= 0x08
		if knownMedia(reserved, int64(len(reserved))) {
			t.Error("a GIF image with a reserved flag set is recognised")
		}
	}
}
