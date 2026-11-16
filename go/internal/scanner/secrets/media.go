package secrets

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
)

// knownMedia reports whether head, the first bytes of a file, is the start of an
// image, font or audio/video container whose STRUCTURE checks out, not merely one
// that opens with the right magic bytes. A recognised container's payload is
// compressed or entropy-coded data in a format the search does not decode, so
// such a file is read as raw bytes, its embedded zlib streams are decoded, and
// the answer says the rest is not covered. The exemption exists so that the
// pictures and fonts of an ordinary repository do not make every verification
// unknown. It must therefore not be a header anyone can type: "GIF89a" followed
// by an xz stream is not a picture (verification pass 1: DE5-04, redteam5-09).
//
// Each check walks the container's own framing as far as the sample reaches:
// PNG chunk lengths, types and CRCs; GIF blocks; JPEG segments; RIFF, WOFF and
// sfnt headers against the file's length when it is known; the first ISO-BMFF
// boxes; Ogg, FLAC, ID3 and ICO headers. Anything that does not parse is not
// media. What this does not do is prove the payload is a picture: a container can
// carry arbitrary bytes in a comment or application segment, and the checks
// cannot tell those from data. It recognises content, never a name, so a file
// that is only called .png is not one.
func knownMedia(head []byte, size int64) bool {
	switch {
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return validPNG(head)
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		return validJPEG(head)
	case bytes.HasPrefix(head, []byte("GIF87a")), bytes.HasPrefix(head, []byte("GIF89a")):
		return validGIF(head, size)
	case len(head) >= 12 && bytes.Equal(head[:4], []byte("RIFF")) && (bytes.Equal(head[8:12], []byte("WEBP")) || bytes.Equal(head[8:12], []byte("WAVE"))):
		return validRIFF(head, size)
	case bytes.HasPrefix(head, []byte("wOFF")), bytes.HasPrefix(head, []byte("wOF2")):
		return validWOFF(head, size)
	case bytes.HasPrefix(head, []byte{0, 1, 0, 0}), bytes.HasPrefix(head, []byte("OTTO")), bytes.HasPrefix(head, []byte("true")):
		return validSFNT(head, size)
	case bytes.HasPrefix(head, []byte("ID3")):
		return validID3(head)
	case bytes.HasPrefix(head, []byte("OggS")):
		return validOgg(head)
	case bytes.HasPrefix(head, []byte("fLaC")):
		return validFLAC(head)
	case len(head) >= 12 && bytes.Equal(head[4:8], []byte("ftyp")):
		return validISOBMFF(head, size)
	case bytes.HasPrefix(head, []byte{0, 0, 1, 0}):
		return validICO(head, size)
	}
	return false
}

func isFourCC(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, c := range b[:4] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func isLetters4(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, c := range b[:4] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// validPNG walks the chunks that lie inside the sample: IHDR first and 13 bytes
// long, every chunk type four letters, every complete chunk's CRC right. A chunk
// that runs past the sample ends the walk; its zlib data is decoded (or reported
// lost) by the embedded-stream search.
func validPNG(head []byte) bool {
	i := 8
	first := true
	for {
		if len(head)-i < 12 {
			return !first
		}
		n := int64(binary.BigEndian.Uint32(head[i:]))
		typ := head[i+4 : i+8]
		if !isLetters4(typ) || n > 1<<31-1 {
			return false
		}
		if first && (string(typ) != "IHDR" || n != 13) {
			return false
		}
		first = false
		end := int64(i) + 8 + n + 4
		if end > int64(len(head)) {
			return true
		}
		if crc32.ChecksumIEEE(head[i+4:int(end)-4]) != binary.BigEndian.Uint32(head[end-4:]) {
			return false
		}
		i = int(end)
		if string(typ) == "IEND" {
			return true
		}
	}
}

// validGIF walks the header, the logical screen descriptor and the blocks inside
// the sample, and holds every field it reads to what a GIF encoder writes
// (OR-14): a header followed by noise is not a picture, however the noise
// happens to frame as blocks.
//
//   - the screen has a width and a height, and a background colour index that
//     lies inside the global colour table when there is one;
//   - an extension is one of the four the format defines, with the fixed first
//     block size it has (graphic control 4, application 11, plain text 12), the
//     application identifier printable, and a graphic control extension is that
//     one block and its terminator;
//   - a comment extension is text: valid UTF-8 without control characters, so a
//     stream is not passed through one;
//   - an image has a width and a height, lies inside the screen, sets no
//     reserved flag, and starts its data with an LZW code size of 2 to 8;
//   - a trailer is the last byte of the file when the file's length is known.
//
// What it cannot do is prove an application extension or the image data is not a
// payload: they are arbitrary bytes by design (see knownMedia).
func validGIF(head []byte, size int64) bool {
	if len(head) < 13 {
		return false
	}
	screenW, screenH := int(binary.LittleEndian.Uint16(head[6:])), int(binary.LittleEndian.Uint16(head[8:]))
	if screenW == 0 || screenH == 0 {
		return false
	}
	i := 13
	if head[10]&0x80 != 0 {
		colours := 2 << (head[10] & 7)
		if int(head[11]) >= colours {
			return false
		}
		i += 3 * colours
	}
	// subBlocks reads the data sub-blocks that start at head[i]: the size of the
	// first, how many there are before the terminator, their concatenation when
	// keep is set, and whether a terminator was read inside the sample.
	subBlocks := func(keep bool) (first, count int, data []byte, ended bool) {
		first = -1
		for {
			if i >= len(head) {
				return first, count, data, false
			}
			n := int(head[i])
			i++
			if first < 0 {
				first = n
			}
			if n == 0 {
				return first, count, data, true
			}
			count++
			if keep {
				data = append(data, head[i:min(i+n, len(head))]...)
			}
			i += n
		}
	}
	isText := func(b []byte) bool {
		for _, c := range b {
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7f {
				return false
			}
		}
		return validUTF8Prefix(b)
	}
	blocks := 0
	for i < len(head) {
		switch head[i] {
		case 0x3B:
			if blocks == 0 {
				return false
			}
			return size <= 0 || int64(i)+1 == size
		case 0x21:
			if i+3 > len(head) {
				return blocks > 0
			}
			label := head[i+1]
			i += 2
			start := i
			first, count, data, ended := subBlocks(label == 0xFE || label == 0x01)
			switch label {
			case 0xF9: // graphic control: one block of 4 bytes, then the terminator
				if first != 4 || (ended && count != 1) {
					return false
				}
			case 0xFF: // application: an 11-byte identifier (8 + 3) of printable bytes, then data
				if first != 11 {
					return false
				}
				if id := head[start+1 : min(start+12, len(head))]; !isPrintable(id) {
					return false
				}
			case 0x01: // plain text: a 12-byte header, then text blocks
				if first != 12 {
					return false
				}
			case 0xFE: // comment: text
				if !isText(data) {
					return false
				}
			default:
				return false
			}
			if !ended {
				return true
			}
		case 0x2C:
			if i+10 > len(head) {
				return true
			}
			left, top := int(binary.LittleEndian.Uint16(head[i+1:])), int(binary.LittleEndian.Uint16(head[i+3:]))
			w, h := int(binary.LittleEndian.Uint16(head[i+5:])), int(binary.LittleEndian.Uint16(head[i+7:]))
			flags := head[i+9]
			if w == 0 || h == 0 || left+w > screenW || top+h > screenH || flags&0x18 != 0 {
				return false
			}
			i += 10
			if flags&0x80 != 0 {
				i += 3 << (flags&7 + 1)
			}
			if i >= len(head) {
				return true
			}
			if head[i] < 2 || head[i] > 8 { // LZW minimum code size
				return false
			}
			i++
			if _, _, _, ended := subBlocks(false); !ended {
				return true
			}
		default:
			return false
		}
		blocks++
	}
	return blocks > 0
}

// isPrintable reports whether every byte of b is printable ASCII.
func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// validJPEG walks the marker segments up to the start of the entropy-coded scan.
func validJPEG(head []byte) bool {
	i := 2
	segments := 0
	for i+4 <= len(head) {
		if head[i] != 0xFF {
			return false
		}
		m := head[i+1]
		switch {
		case m == 0xFF:
			i++
			continue
		case m == 0xDA:
			return segments > 0 // the scan: entropy-coded data follows
		case m == 0xD9:
			return segments > 0
		case m >= 0xD0 && m <= 0xD7, m == 0x01:
			i += 2
			continue
		case m == 0xC8 || (m >= 0xF0 && m <= 0xFD) || m == 0x00:
			return false
		}
		n := int(binary.BigEndian.Uint16(head[i+2:]))
		if n < 2 {
			return false
		}
		body := head[min(i+4, len(head)):min(i+2+n, len(head))]
		switch {
		case m == 0xE0 && !(bytes.HasPrefix(body, []byte("JFIF\x00")) || bytes.HasPrefix(body, []byte("JFXX\x00"))):
			return false
		case i+2+n > len(head):
			// A segment longer than the sample is credible only for the two kinds
			// that really are large: Exif data and an ICC profile or XMP packet,
			// each of which names itself.
			return (m == 0xE1 && (bytes.HasPrefix(body, []byte("Exif\x00\x00")) || bytes.HasPrefix(body, []byte("http://ns.adobe.com/xap/1.0/\x00")))) ||
				(m == 0xE2 && (bytes.HasPrefix(body, []byte("ICC_PROFILE\x00")) || bytes.HasPrefix(body, []byte("MPF\x00"))))
		}
		if m == 0xFE { // a comment is text
			end := min(i+2+n, len(head))
			body := head[min(i+4, end):end]
			for _, c := range body {
				if c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f {
					return false
				}
			}
		}
		i += 2 + n
		segments++
	}
	return segments > 0
}

func validRIFF(head []byte, size int64) bool {
	total := int64(binary.LittleEndian.Uint32(head[4:])) + 8
	if size > 0 && total != size && total != size-1 { // the RIFF pad byte
		return false
	}
	if len(head) < 20 || !isFourCC(head[12:16]) {
		return false
	}
	switch string(head[8:12]) {
	case "WAVE":
		return string(head[12:16]) == "fmt "
	default:
		return bytes.HasPrefix(head[12:], []byte("VP8"))
	}
}

func validWOFF(head []byte, size int64) bool {
	if len(head) < 20 {
		return false
	}
	if size > 0 && int64(binary.BigEndian.Uint32(head[8:])) != size {
		return false
	}
	tables := int(binary.BigEndian.Uint16(head[12:]))
	return tables >= 1 && tables <= 255 && sfntFlavor(head[4:8])
}

func sfntFlavor(b []byte) bool {
	return bytes.Equal(b, []byte{0, 1, 0, 0}) || string(b) == "OTTO" || string(b) == "true" || string(b) == "ttcf"
}

// validSFNT checks an OpenType/TrueType table directory: the table count's
// search fields follow from it, every tag is four printable bytes, and each table
// lies inside the file when its length is known.
func validSFNT(head []byte, size int64) bool {
	if len(head) < 12 {
		return false
	}
	n := int(binary.BigEndian.Uint16(head[4:]))
	if n < 1 || n > 512 {
		return false
	}
	pow, sel := 1, 0
	for pow*2 <= n {
		pow *= 2
		sel++
	}
	if int(binary.BigEndian.Uint16(head[6:])) != pow*16 || int(binary.BigEndian.Uint16(head[8:])) != sel || int(binary.BigEndian.Uint16(head[10:])) != n*16-pow*16 {
		return false
	}
	dirEnd := int64(12 + 16*n)
	for k := 0; k < n && 12+16*(k+1) <= len(head); k++ {
		e := head[12+16*k:]
		if !isFourCC(e) {
			return false
		}
		off, length := int64(binary.BigEndian.Uint32(e[8:])), int64(binary.BigEndian.Uint32(e[12:]))
		if off < dirEnd || (size > 0 && off+length > size) {
			return false
		}
	}
	return true
}

func validID3(head []byte) bool {
	if len(head) < 10 || head[3] < 2 || head[3] > 4 || head[4] == 0xFF {
		return false
	}
	for _, c := range head[6:10] {
		if c&0x80 != 0 {
			return false
		}
	}
	tag := 10 + (int(head[6])<<21 | int(head[7])<<14 | int(head[8])<<7 | int(head[9]))
	if tag+2 <= len(head) {
		// An MPEG audio frame (or padding up to one) follows the tag.
		j := tag
		for j < len(head) && head[j] == 0 {
			j++
		}
		return j+2 > len(head) || (head[j] == 0xFF && head[j+1]&0xE0 == 0xE0)
	}
	return true
}

func validOgg(head []byte) bool {
	if len(head) < 28 || head[4] != 0 || head[5]&0x02 == 0 {
		return false
	}
	segs := int(head[26])
	if segs < 1 || len(head) < 27+segs+8 {
		return false
	}
	pkt := head[27+segs:]
	for _, id := range []string{"\x01vorbis", "OpusHead", "\x7fFLAC", "\x80theora", "Speex   "} {
		if bytes.HasPrefix(pkt, []byte(id)) {
			return true
		}
	}
	return false
}

func validFLAC(head []byte) bool {
	// The first metadata block is STREAMINFO: type 0, 34 bytes.
	return len(head) >= 8 && head[4]&0x7f == 0 && head[5] == 0 && head[6] == 0 && head[7] == 34
}

// isoTopLevel are the box types a base media file (MP4, MOV, 3GP, HEIC, AVIF,
// fragmented MP4) may carry at its top level. A box type outside this set is not
// the framing of such a file, whatever its bytes spell.
var isoTopLevel = map[string]bool{
	"moov": true, "mdat": true, "moof": true, "mfra": true, "meta": true, "sidx": true, "ssix": true,
	"styp": true, "pdin": true, "prft": true, "emsg": true, "etyp": true, "uuid": true,
	"free": true, "skip": true, "wide": true,
}

// validISOBMFF walks the top-level boxes inside the sample (R5-12): the ftyp box
// with a whole number of four-letter brands, then each box whose header lies in
// the sample must be one of the top-level types above with a size that is
// consistent (at least a header, within the file when its length is known), and
// a padding box (free, skip, wide) must hold zeros, because padding is the one
// box whose content is nothing and so the one place a typed payload would hide.
// An ftyp box followed by noise, or by a hand-typed box with a printable type, is
// not media. A payload inside mdat or another content box is not detectable
// from framing (see knownMedia).
func validISOBMFF(head []byte, size int64) bool {
	n := int64(binary.BigEndian.Uint32(head))
	if n < 16 || n > 512 || n%4 != 0 || !isFourCC(head[8:12]) || (size > 0 && n > size) {
		return false
	}
	for off := int64(16); off+4 <= n && off+4 <= int64(len(head)); off += 4 {
		if !isFourCC(head[off:]) {
			return false
		}
	}
	off := n
	for off+8 <= int64(len(head)) {
		box := head[off:]
		m, hdr := int64(binary.BigEndian.Uint32(box)), int64(8)
		typ := string(box[4:8])
		if !isoTopLevel[typ] {
			return false
		}
		switch {
		case m == 1: // a 64-bit size follows the type
			if off+16 > int64(len(head)) {
				return true
			}
			m, hdr = int64(binary.BigEndian.Uint64(box[8:])), 16
			if m < 16 {
				return false
			}
		case m == 0: // the box runs to the end of the file
			if size <= 0 {
				return true
			}
			m = size - off
		case m < 8:
			return false
		}
		if m < hdr || (size > 0 && off+m > size) {
			return false
		}
		if typ == "free" || typ == "skip" || typ == "wide" {
			body := head[min(off+hdr, int64(len(head))):min(off+m, int64(len(head)))]
			for _, c := range body {
				if c != 0 {
					return false
				}
			}
		}
		if off+m >= int64(len(head)) {
			return true
		}
		off += m
	}
	return true
}

func validICO(head []byte, size int64) bool {
	if len(head) < 22 {
		return false
	}
	count := int(binary.LittleEndian.Uint16(head[4:]))
	if count < 1 || count > 255 {
		return false
	}
	for k := 0; k < count && 6+16*(k+1) <= len(head); k++ {
		e := head[6+16*k:]
		off, length := int64(binary.LittleEndian.Uint32(e[12:])), int64(binary.LittleEndian.Uint32(e[8:]))
		if e[3] != 0 || off < int64(6+16*count) || (size > 0 && off+length > size) {
			return false
		}
	}
	return true
}
