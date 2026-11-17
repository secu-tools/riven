// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package pieceio

import (
	"strings"
	"testing"
)

// TestADamagedSheetIsNamedAsOne checks a page that is a recovery sheet but whose
// piece text does not read is reported as a damaged sheet, which tells the user
// what to look at, rather than as something that is not a piece at all.
func TestADamagedSheetIsNamedAsOne(t *testing.T) {
	page := `<pre id="` + sheetMarker + `">NOT BASE32 AT ALL !!</pre>`
	if _, _, err := decodeDetail([]byte(page)); err == nil || !strings.Contains(err.Error(), "recovery sheet") {
		t.Fatalf("got %v", err)
	}
}

// TestSheetMarkupThatEndsEarlyIsNotASheet checks the sheet scanners refuse a
// page whose markup stops short, rather than read past it.
func TestSheetMarkupThatEndsEarlyIsNotASheet(t *testing.T) {
	for _, page := range []string{
		`<pre id="` + sheetMarker + `"`,           // the tag never closes
		`<pre id="` + sheetMarker + `">ABCD EFGH`, // the text never ends
	} {
		if _, ok := sheetBody([]byte(page)); ok {
			t.Errorf("%q was read as a sheet", page)
		}
	}
	for _, page := range []string{
		`<img src="` + sheetQRSource + `iVBORw0KGgo`,  // the attribute never closes
		`<img src="` + sheetQRSource + `not*base64">`, // the image is not base64
	} {
		if _, ok := sheetQR([]byte(page)); ok {
			t.Errorf("%q gave a QR code", page)
		}
	}
}

// TestAnUnknownFormatIsRefused checks Encode names a format it does not have,
// and that one describes itself as nothing rather than as another.
func TestAnUnknownFormatIsRefused(t *testing.T) {
	if _, err := Encode(make([]byte, 100), Format("telegram"), 0); err == nil {
		t.Fatal("an unknown format was encoded")
	}
	if d := Format("telegram").Describe(); d != "" {
		t.Fatalf("an unknown format describes itself as %q", d)
	}
}

// TestBase32GroupsEndWithTheText checks the last group may be short and still
// ends its line.
func TestBase32GroupsEndWithTheText(t *testing.T) {
	if got := groupBase32("ABCDEFG"); got != "ABCD EFG\n" {
		t.Fatalf("got %q", got)
	}
}
