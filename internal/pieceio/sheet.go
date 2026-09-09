// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"strings"

	"github.com/secu-tools/riven/internal/qrcode"
)

// SheetInfo is what a recovery sheet states about the piece it carries.
type SheetInfo struct {
	Serial int    // this piece
	Total  int    // pieces in the set
	Needed int    // pieces required to rebuild
	Name   string // base name of the original input, for the reader's reference
}

// sheetMarker delimits the piece text inside the page, so a saved sheet can be
// read back as an input file.
const sheetMarker = "piece-text"

// Sheet layout constants, measured from the template at its printed font size.
// They only have to be close: they drive an estimate and a limit, not the layout
// itself, which the browser does.
const (
	sheetCharsPerLine = 39 // 8 groups of 4, separated by spaces
	sheetLinesPerPage = 44

	// SheetMaxPages is the most pages one piece may take. Past this it is not a
	// sheet any more, and base32 or binary is the format that was wanted.
	SheetMaxPages = 16
)

// SheetPages estimates how many printed pages a piece takes, always at least one.
func SheetPages(pieceLen int) int {
	chars := len(base32.StdEncoding.EncodeToString(make([]byte, pieceLen+checksumLen)))
	lines := (chars + sheetCharsPerLine - 1) / sheetCharsPerLine
	pages := (lines + sheetLinesPerPage - 1) / sheetLinesPerPage
	if pages < 1 {
		return 1
	}
	return pages
}

// SheetMaxPiece is the largest piece a sheet will carry.
var SheetMaxPiece = sheetMaxPiece()

func sheetMaxPiece() int {
	// Invert SheetPages: characters that fit, back to piece bytes, less the
	// checksum. Base32 is 8 characters per 5 bytes.
	chars := SheetMaxPages * sheetLinesPerPage * sheetCharsPerLine
	return chars/8*5 - checksumLen
}

var errSheetTooLarge = errors.New("this piece would take more printed pages than a sheet is for; use base32 or binary")

// EncodeSheet renders a printable page carrying one piece.
//
// Unlike the other formats, a sheet is meant to be understood by whoever finds
// it: it names the tool, says how many pieces are needed, and carries the piece
// as a QR code and as base32 text. It is therefore the one format that
// identifies itself, which is the trade-off for being usable by someone who was
// not told what the file is.
//
// A piece too large for a QR code still gets a sheet, with the text alone. A
// piece too large to print sensibly does not: see SheetMaxPages.
func EncodeSheet(piece []byte, info SheetInfo, qrScale int) ([]byte, string, error) {
	if len(piece) > SheetMaxPiece {
		return nil, "", errSheetTooLarge
	}
	text := groupBase32(base32.StdEncoding.EncodeToString(withChecksum(piece)))
	pages := SheetPages(len(piece))

	var qrTag, note string
	if QRFits(len(piece)) {
		png, level, err := qrcode.Encode(piece, qrScale)
		if err != nil {
			return nil, "", err
		}
		qrTag = fmt.Sprintf(`<img alt="piece %d" src="data:image/png;base64,%s">`,
			info.Serial, base64.StdEncoding.EncodeToString(png))
		note = fmt.Sprintf("error correction %s (~%d%% recoverable)", level.Name, level.Recovery)
	} else {
		qrTag = fmt.Sprintf(`<p class="none">This piece is %d bytes, too large for a QR code. `+
			`The text below carries it instead.</p>`, len(piece))
		note = "too large for a QR code; text only"
	}

	// A sheet that runs to several pages has to say so on every page, or a lost
	// page goes unnoticed until the day it is needed.
	pageNote := ""
	if pages > 1 {
		pageNote = fmt.Sprintf(
			`<p class="warn">This piece is about %d printed pages. Keep them together and in order: `+
				`the text is one continuous block and every page of it is needed.</p>`, pages)
		note += fmt.Sprintf("; about %d pages per piece", pages)
	}

	name := info.Name
	if name == "" {
		name = "(not recorded)"
	}

	page := strings.NewReplacer(
		"{{SERIAL}}", fmt.Sprint(info.Serial),
		"{{TOTAL}}", fmt.Sprint(info.Total),
		"{{NEEDED}}", fmt.Sprint(info.Needed),
		"{{NAME}}", html.EscapeString(name),
		"{{QR}}", qrTag,
		"{{PAGENOTE}}", pageNote,
		"{{MARKER}}", sheetMarker,
		"{{TEXT}}", html.EscapeString(text),
	).Replace(sheetTemplate)

	return []byte(page), note, nil
}

// sheetBody extracts the piece text from a saved sheet. It returns false when
// the input is not a sheet.
func sheetBody(raw []byte) ([]byte, bool) {
	open := []byte(`id="` + sheetMarker + `"`)
	i := bytes.Index(raw, open)
	if i < 0 {
		return nil, false
	}
	rest := raw[i:]
	start := bytes.IndexByte(rest, '>')
	if start < 0 {
		return nil, false
	}
	rest = rest[start+1:]
	end := bytes.Index(rest, []byte("</pre>"))
	if end < 0 {
		return nil, false
	}
	return rest[:end], true
}

// sheetTemplate is the printable page. It is self-contained: no external styles,
// scripts or images, so it renders the same offline and years from now.
const sheetTemplate = `<!doctype html>
<!-- No link, script or image: this page has to render offline, years from now. -->
<html lang="en">
<head>
<meta charset="utf-8">
<title>Riven recovery piece {{SERIAL}} of {{TOTAL}}</title>
<style>
  body { font-family: sans-serif; margin: 2em; max-width: 40em; color: #000; }
  h1 { font-size: 1.4em; margin-bottom: 0.2em; }
  .lead { font-size: 1.1em; margin-top: 0; }
  .box { border: 1px solid #000; padding: 0.8em 1em; margin: 1em 0; }
  pre { font-family: monospace; font-size: 0.95em; line-height: 1.5;
        white-space: pre-wrap; word-break: break-all; margin: 0; }
  img { max-width: 100%; height: auto; }
  .none { font-style: italic; }
  .warn { border: 2px solid #000; padding: 0.6em 1em; font-weight: bold; }
  ol { padding-left: 1.2em; }
  .fill { border-bottom: 1px solid #000; display: inline-block; min-width: 12em; }
  header, footer { font-size: 0.9em; }
  footer { margin-top: 2em; }
  @media print {
    body { margin: 0.5em; max-width: none; }
    /* The identity of the piece must not be left behind on page one. */
    header { position: fixed; top: 0; }
    body { padding-top: 1.6em; }
    /* Keep the code, the instructions and the footer whole. */
    .box, ol, footer, .warn { break-inside: avoid; page-break-inside: avoid; }
    /* The text block is the one thing that may run over pages. */
    #{{MARKER}} { break-inside: auto; page-break-inside: auto; }
  }
</style>
</head>
<body>
<header>Riven recovery piece {{SERIAL}} of {{TOTAL}} - {{NAME}}</header>
<h1>Recovery piece {{SERIAL}} of {{TOTAL}}</h1>
<p class="lead">Any {{NEEDED}} of the {{TOTAL}} pieces rebuild the file. Fewer reveal nothing.</p>
{{PAGENOTE}}
<div class="box">
{{QR}}
</div>

<div class="box">
<pre id="{{MARKER}}">{{TEXT}}</pre>
</div>

<h2>How to use this</h2>
<ol>
  <li>Gather {{NEEDED}} different pieces of this set.</li>
  <li>Get the tool: <code>go install github.com/secu-tools/riven@latest</code></li>
  <li>Get each piece back into a file. Scanning the QR code with any QR reader is
      easiest. Otherwise photograph or scan this page and run it through OCR: the
      text is only A-Z and 2-7, with no characters that look alike, so it reads
      back reliably. Retyping it works too, but there is a lot of it.</li>
  <li>Run <code>riven combine PIECE1 PIECE2 ...</code> and supply the password.
      Spacing, line breaks and capitals in the text do not matter, and a mistake
      is reported rather than silently accepted.</li>
</ol>
<p>The password is not on this sheet and never will be. Without it, and without
{{NEEDED}} pieces, this page reveals nothing about the contents.</p>

<footer>
<p>Original file: {{NAME}}</p>
<p>Stored at: <span class="fill"></span> &nbsp; Date: <span class="fill"></span></p>
</footer>
</body>
</html>
`
