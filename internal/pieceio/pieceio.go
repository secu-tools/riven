// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package pieceio writes pieces in the supported transport formats and reads
// them back, detecting the format from the content rather than the file name.
//
// Every format except the recovery sheet carries the bare piece with no label of
// its own, so none announces which tool produced it. The text formats hide a
// checksum inside the encoded blob, catching a copying mistake without adding
// visible structure. The sheet is the deliberate exception: a printable page
// that explains itself.
package pieceio

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"

	"github.com/secu-tools/riven/internal/format"
	"github.com/secu-tools/riven/internal/qrcode"
)

// Format identifies a transport encoding.
type Format string

const (
	// Binary writes the piece bytes verbatim.
	Binary Format = "binary"
	// Base64 writes the piece as wrapped standard base64 text.
	Base64 Format = "base64"
	// Base32 writes the piece as grouped RFC 4648 base32 text, which is meant to
	// be copied by hand: one case, and no characters that look alike.
	Base32 Format = "base32"
	// QR writes the piece as a QR code PNG.
	QR Format = "qr"
	// Sheet writes a printable page carrying the piece as a QR code and as
	// base32 text, with instructions.
	Sheet Format = "sheet"
	// Words writes the piece as BIP-39 words: by far the largest form, for a
	// piece small enough to write out by hand.
	Words Format = "words"
)

// All returns every supported format, ordered from the most compact to the most
// elaborate. This is presentation order only; detection order is separate and is
// fixed by what each encoding can be confused with (see decodeDetail).
func All() []Format { return []Format{Binary, Base64, Base32, Words, QR, Sheet} }

// Encodable returns the formats Encode produces on its own. A recovery sheet is
// excluded because it has to state which piece it carries, which Encode is not
// told; use EncodeSheet for that one.
func Encodable() []Format { return []Format{Binary, Base64, Base32, Words, QR} }

// Describe is a one-line summary for a menu.
func (f Format) Describe() string {
	switch f {
	case Binary:
		return "binary file, the smallest form"
	case Base64:
		return "base64 text, for a messenger or an email"
	case Base32:
		return "base32 text, grouped for copying by hand"
	case QR:
		return "QR code image, for scanning from paper"
	case Sheet:
		return "printable sheet: QR code, text and instructions"
	case Words:
		return "BIP-39 words, the largest form, for writing out by hand"
	}
	return ""
}

// Extensions applied to the piece base name per format.
const (
	extBinary = ""
	extBase64 = ".txt"
	extBase32 = ".b32.txt"
	extQR     = ".png"
	extSheet  = ".html"
	extWords  = ".words.txt"
)

// base64LineLen wraps base64 output so it survives messengers and printing.
const base64LineLen = 76

// base32 output is grouped for hand copying: blocks of base32GroupLen characters,
// base32GroupsPerLine to a line.
const (
	base32GroupLen      = 4
	base32GroupsPerLine = 8
)

// checksumLen is the CRC-32 appended inside the text formats. It sits inside the
// encoded blob rather than on a line of its own, so the file keeps no visible
// structure that would identify it.
const checksumLen = 4

// names lists the format names for error messages.
func names() []string {
	out := make([]string, 0, len(All()))
	for _, f := range All() {
		out = append(out, string(f))
	}
	return out
}

// ParseFormats resolves a comma-separated list such as "binary,qr" or "all".
func ParseFormats(spec string) ([]Format, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" {
		return []Format{Binary}, nil
	}
	if spec == "all" {
		return All(), nil
	}
	seen := map[Format]bool{}
	var out []Format
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f, err := ParseFormat(part)
		if err != nil {
			return nil, err
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no export format given")
	}
	return out, nil
}

// ParseFormat resolves one format name or alias.
func ParseFormat(name string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "binary", "bin", "raw":
		return Binary, nil
	case "base64", "b64", "text", "txt":
		return Base64, nil
	case "base32", "b32":
		return Base32, nil
	case "qr", "qrcode", "png":
		return QR, nil
	case "sheet", "paper", "print", "html":
		return Sheet, nil
	case "words", "bip39", "mnemonic":
		return Words, nil
	}
	return "", fmt.Errorf("unknown export format %q (use %s, or all)", name, strings.Join(names(), ", "))
}

// String renders the format name.
func (f Format) String() string { return string(f) }

// Encode converts one piece into the bytes to store for the given format.
// qrScale is the QR module size in pixels; values below one use the default.
// note is a human-readable remark about the encoding, empty when there is
// nothing worth saying.
//
// Sheet is not produced here because it needs to state which piece it is; use
// EncodeSheet.
func Encode(piece []byte, f Format, qrScale int) (data []byte, note string, err error) {
	switch f {
	case Binary:
		out := make([]byte, len(piece))
		copy(out, piece)
		return out, "", nil

	case Base64:
		return []byte(wrap(base64.StdEncoding.EncodeToString(withChecksum(piece)))), "", nil

	case Base32:
		return []byte(groupBase32(base32.StdEncoding.EncodeToString(withChecksum(piece)))), "", nil

	case QR:
		png, level, err := qrcode.Encode(piece, qrScale)
		if err != nil {
			return nil, "", err
		}
		note = fmt.Sprintf("error correction %s (~%d%% recoverable)", level.Name, level.Recovery)
		if level.Weakest() {
			note += "; near capacity, print at high quality"
		}
		return png, note, nil

	case Words:
		if len(piece) > Bip39MaxPiece {
			return nil, "", errBip39TooLarge
		}
		return []byte(encodeBip39(piece)), fmt.Sprintf("%d words per piece", Bip39Words(len(piece))), nil

	case Sheet:
		return nil, "", errors.New("a recovery sheet needs the piece number; use EncodeSheet")

	default:
		return nil, "", fmt.Errorf("unknown export format %q", f)
	}
}

// withChecksum appends a CRC-32 of the piece, so a text format catches a copying
// mistake before the piece itself is tried. It sits inside the encoded blob, so
// the file remains one run of characters.
func withChecksum(piece []byte) []byte {
	out := make([]byte, 0, len(piece)+checksumLen)
	out = append(out, piece...)
	var sum [checksumLen]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE(piece))
	return append(out, sum[:]...)
}

// stripChecksum removes a trailing CRC-32 when it matches. A mismatch is not an
// error here: the blob is returned whole and the caller is told the check did not
// pass, so text without a checksum still works and damaged text gets a message
// naming the likely cause.
func stripChecksum(b []byte) (piece []byte, verified bool) {
	if len(b) < format.MinPieceLen+checksumLen {
		return b, false
	}
	body, sum := b[:len(b)-checksumLen], b[len(b)-checksumLen:]
	if crc32.ChecksumIEEE(body) == binary.BigEndian.Uint32(sum) {
		return body, true
	}
	return b, false
}

// Path returns the output path for a piece in the given format.
func Path(dir, base string, f Format) string {
	switch f {
	case Base64:
		return filepath.Join(dir, base+extBase64)
	case Base32:
		return filepath.Join(dir, base+extBase32)
	case QR:
		return filepath.Join(dir, base+extQR)
	case Sheet:
		return filepath.Join(dir, base+extSheet)
	case Words:
		return filepath.Join(dir, base+extWords)
	default:
		return filepath.Join(dir, base+extBinary)
	}
}

// Write stores data at path with owner-only permissions.
func Write(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %q: %w", path, err)
	}
	return nil
}

// QRFits reports whether a piece of the given size can be encoded as a QR code.
func QRFits(pieceLen int) bool { return qrcode.Fits(pieceLen) }

// QRLevelFor reports the error correction level a piece of this size will get.
func QRLevelFor(pieceLen int) (name string, recovery int, weakest, ok bool) {
	l, err := qrcode.SelectLevel(pieceLen)
	if err != nil {
		return "", 0, false, false
	}
	return l.Name, l.Recovery, l.Weakest(), true
}

// QRMaxBytes is the largest piece that fits in a QR code.
var QRMaxBytes = qrcode.MaxBytes

// QRPhotoFriendlyBytes is the piece size below which a printed code still reads
// from a poor photograph: small in frame, angled, rotated and blurred. Larger
// symbols have smaller modules and need a flatter, sharper shot.
var QRPhotoFriendlyBytes = qrcode.PhotoFriendlyBytes

// QRTooLargeMessage explains why a piece will not fit, and suggests compressing
// the original input only when that could plausibly close the gap. Compressing
// the piece itself never helps because it is encrypted.
func QRTooLargeMessage(pieceLen int) string {
	msg := fmt.Sprintf("piece is %d bytes; a QR code holds at most %d", pieceLen, QRMaxBytes)
	if pieceLen <= QRMaxBytes*16 {
		msg += ". Compress the original file before splitting, or use fewer cascade layers"
	}
	return msg
}

// Detected describes the format a loaded piece arrived in.
type Detected struct {
	Format Format
	Path   string

	// Verified reports that the stored form carried its own integrity check and
	// it passed. False for a text file with no checksum, or damaged text.
	Verified bool
}

// MaxStoredLen bounds a file Load will read.
//
// This is a backstop against a file that claims an absurd size, not a limit on
// how large a piece may be: the whole file is read before anything is decoded,
// so without it os.ReadFile would try to allocate whatever was named. It sits
// far above any piece that could actually be combined, since rebuilding needs
// several times the piece size in memory at once.
const MaxStoredLen = 16 << 30

// Load reads a file and returns the piece bytes plus what was detected.
func Load(path string) ([]byte, Detected, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, Detected{}, err
	}
	if !st.Mode().IsRegular() {
		return nil, Detected{}, fmt.Errorf("%q: not a regular file", path)
	}
	if st.Size() > MaxStoredLen {
		return nil, Detected{}, fmt.Errorf("%q: %d bytes is larger than a piece can be (limit %d)",
			path, st.Size(), MaxStoredLen)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, Detected{}, err
	}
	piece, det, err := decodeDetail(raw)
	if err != nil {
		return nil, Detected{}, fmt.Errorf("%q: %w", path, err)
	}
	det.Path = path
	return piece, det, nil
}

// Decode turns stored bytes back into a piece, detecting the format.
func Decode(raw []byte) ([]byte, Format, error) {
	piece, det, err := decodeDetail(raw)
	return piece, det.Format, err
}

// decodeDetail is Decode plus whether an integrity check passed.
//
// The order matters, and is the one documented in format.md section 9: each
// encoding is tried before any it could be mistaken for.
func decodeDetail(raw []byte) ([]byte, Detected, error) {
	if len(raw) == 0 {
		return nil, Detected{}, errors.New("file is empty")
	}
	if qrcode.IsImage(raw) {
		piece, err := qrcode.Decode(raw)
		if err != nil {
			return nil, Detected{}, err
		}
		return piece, Detected{Format: QR, Verified: true}, nil
	}
	if body, ok := sheetBody(raw); ok {
		if piece, verified, ok := tryBase32(body); ok {
			return piece, Detected{Format: Sheet, Verified: verified}, nil
		}
		return nil, Detected{}, errors.New("this is a recovery sheet, but its piece text did not decode")
	}
	if piece, verified, ok := tryBip39(raw); ok {
		return piece, Detected{Format: Words, Verified: verified}, nil
	}
	if piece, verified, ok := tryBase32(raw); ok {
		return piece, Detected{Format: Base32, Verified: verified}, nil
	}
	if piece, verified, ok := tryBase64(raw); ok {
		return piece, Detected{Format: Base64, Verified: verified}, nil
	}
	if len(raw) < format.MinPieceLen {
		return nil, Detected{}, fmt.Errorf("file is too small to be a piece (%d bytes)", len(raw))
	}
	return raw, Detected{Format: Binary, Verified: true}, nil
}

// tryBase64 decodes raw as base64 text, ignoring line breaks and surrounding
// whitespace. It requires the whole input to be base64 and the result to be large
// enough to be a piece, so binary input is never misread.
func tryBase64(raw []byte) (piece []byte, verified, ok bool) {
	return tryEncoded(raw, isBase64Char, false, false, 4, base64.StdEncoding.DecodeString)
}

// tryBase32 decodes raw as grouped base32, accepting either case and ignoring the
// spaces and hyphens a person may add while copying.
func tryBase32(raw []byte) (piece []byte, verified, ok bool) {
	return tryEncoded(raw, isBase32Char, true, true, 8, base32.StdEncoding.DecodeString)
}

// tryEncoded collects raw against an alphabet, checks it groups evenly, decodes it,
// and requires the result to be large enough to be a piece, so binary input is
// never misread.
func tryEncoded(raw []byte, valid func(byte) bool, skipHyphen, foldCase bool, group int, decode func(string) ([]byte, error)) (piece []byte, verified, ok bool) {
	s, ok := collect(raw, valid, skipHyphen, foldCase)
	if !ok || len(s)%group != 0 {
		return nil, false, false
	}
	decoded, err := decode(s)
	if err != nil || len(decoded) < format.MinPieceLen {
		return nil, false, false
	}
	p, v := stripChecksum(decoded)
	return p, v, true
}

// collect strips separators and keeps the rest, failing if any byte is outside
// the alphabet. skipHyphen also treats '-' as a separator, and foldCase folds
// letters to upper case, which base32 allows.
func collect(raw []byte, valid func(byte) bool, skipHyphen, foldCase bool) (string, bool) {
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '-':
			if skipHyphen {
				continue
			}
		}
		if c >= 0x80 || !valid(c) {
			return "", false
		}
		if foldCase && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		sb.WriteByte(c)
	}
	if sb.Len() == 0 {
		return "", false
	}
	return sb.String(), true
}

func isBase64Char(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=':
		return true
	}
	return false
}

func isBase32Char(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return true
	case c >= '2' && c <= '7', c == '=':
		return true
	}
	return false
}

// wrap breaks base64 into fixed-width lines.
func wrap(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + len(s)/base64LineLen + 1)
	for i := 0; i < len(s); i += base64LineLen {
		end := i + base64LineLen
		if end > len(s) {
			end = len(s)
		}
		sb.WriteString(s[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// groupBase32 spaces base32 into short blocks, so a person copying it can keep
// their place and check a line at a time.
func groupBase32(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + len(s)/base32GroupLen + 8)
	for i := 0; i < len(s); i += base32GroupLen {
		end := i + base32GroupLen
		if end > len(s) {
			end = len(s)
		}
		sb.WriteString(s[i:end])
		group := i/base32GroupLen + 1
		switch {
		case end == len(s):
			sb.WriteByte('\n')
		case group%base32GroupsPerLine == 0:
			sb.WriteByte('\n')
		default:
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}
