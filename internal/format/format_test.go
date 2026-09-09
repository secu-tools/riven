// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package format

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/secu-tools/riven/internal/cascade"
	"github.com/secu-tools/riven/internal/kdf"
)

var fast = kdf.Params{Memory: 8 * 1024, Time: 1, Par: 1}

func buildInput(share []byte, pad int) EncodeInput {
	setID := make([]byte, setIDLen)
	rand.Read(setID)
	return EncodeInput{
		SetID:       setID,
		K:           3,
		N:           5,
		Serial:      2,
		Encrypted:   true,
		RecordAlgo:  true,
		RecordKDF:   true,
		PayloadLen:  uint64(len(share)),
		PayloadHash: Hash(share),
		Layers:      []cascade.Descriptor{{Kind: cascade.Password, SchemeID: 1, Recorded: true}},
		Share:       share,
		PadLen:      pad,
		Passwords:   [][]byte{[]byte("password")},
		Params:      fast,
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	share := []byte("this is a shamir share of some payload")
	piece, err := Encode(buildInput(share, 40))
	if err != nil {
		t.Fatal(err)
	}
	m, params, err := Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if params != fast {
		t.Fatalf("recovered params %+v, want %+v", params, fast)
	}
	if m.K != 3 || m.N != 5 || m.Serial != 2 || !m.Encrypted {
		t.Fatalf("bad manifest: %+v", m)
	}
	if !m.AlgoStored || !m.KDFStored {
		t.Fatalf("recording flags lost: %+v", m)
	}
	if !bytes.Equal(m.Share, share) {
		t.Fatal("share mismatch")
	}
	if len(m.Layers) != 1 || m.Layers[0].SchemeID != 1 || !m.Layers[0].Recorded {
		t.Fatalf("layer descriptor mismatch: %+v", m.Layers)
	}
	if m.Version != Version {
		t.Fatalf("version %d", m.Version)
	}
}

// TestCreatorFieldsRoundTrip checks the build identity written into a piece comes
// back unchanged, and that omitting it yields empty strings rather than an error.
func TestCreatorFieldsRoundTrip(t *testing.T) {
	in := buildInput([]byte("share bytes for creator test"), 16)
	in.CreatorVersion = "1.2.3.45"
	in.CreatorCommit = "0badc0de"
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.CreatorVersion != "1.2.3.45" || m.CreatorCommit != "0badc0de" {
		t.Fatalf("creator fields: got version %q commit %q", m.CreatorVersion, m.CreatorCommit)
	}

	// Unset creator fields round-trip as empty.
	bare := buildInput([]byte("no creator recorded"), 0)
	piece, err = Encode(bare)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err = Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.CreatorVersion != "" || m.CreatorCommit != "" {
		t.Fatalf("expected empty creator fields, got %q / %q", m.CreatorVersion, m.CreatorCommit)
	}
}

// TestCreatorFieldsBounded checks an over-long creator string is refused rather
// than silently truncated or overflowing the field.
func TestCreatorFieldsBounded(t *testing.T) {
	in := buildInput([]byte("share"), 0)
	in.CreatorVersion = strings.Repeat("v", MaxCreatorLen+1)
	if _, err := Encode(in); err == nil {
		t.Fatal("a creator version over the limit must be refused")
	}
}

// TestKDFRecoveredFromPiece checks that any encodable cost is recovered from the
// masked byte without the caller supplying it.
func TestKDFRecoveredFromPiece(t *testing.T) {
	for _, p := range []kdf.Params{
		{Memory: 8 * 1024, Time: 1, Par: 1},
		{Memory: 16 * 1024, Time: 8, Par: 8},
		{Memory: 32 * 1024, Time: 3, Par: 2},
	} {
		in := buildInput([]byte("share"), 0)
		in.Params = p
		piece, err := Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		_, got, err := Decode(piece, [][]byte{[]byte("password")}, nil)
		if err != nil {
			t.Fatalf("%+v: %v", p, err)
		}
		if got != p {
			t.Fatalf("recovered %+v, want %+v", got, p)
		}
	}
}

// TestHiddenKDFNeedsOverride checks that a piece with an unrecorded cost cannot
// be opened without being told the parameters.
func TestHiddenKDFNeedsOverride(t *testing.T) {
	in := buildInput([]byte("share bytes"), 8)
	in.RecordKDF = false
	// Use a non-default cost so a lucky mask cannot coincide with it.
	in.Params = kdf.Params{Memory: 16 * 1024, Time: 5, Par: 2}
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	// The masked byte is random, so decoding without an override almost never
	// picks the right cost.
	if _, _, err := Decode(piece, [][]byte{[]byte("password")}, nil); err == nil {
		t.Skip("random cost byte happened to match the real cost")
	}
	m, got, err := Decode(piece, [][]byte{[]byte("password")}, &in.Params)
	if err != nil {
		t.Fatal(err)
	}
	if got != in.Params {
		t.Fatalf("params %+v", got)
	}
	if m.KDFStored {
		t.Fatal("KDFStored should be false")
	}
}

func TestHiddenAlgoNotRecorded(t *testing.T) {
	in := buildInput([]byte("share"), 0)
	in.RecordAlgo = false
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.AlgoStored {
		t.Fatal("AlgoStored should be false")
	}
	if len(m.Layers) != 1 {
		t.Fatalf("layer count should survive: %+v", m.Layers)
	}
	if m.Layers[0].SchemeID != 0 || m.Layers[0].Recorded {
		t.Fatalf("algorithm leaked: %+v", m.Layers[0])
	}
}

func TestWrongPassword(t *testing.T) {
	piece, _ := Encode(buildInput([]byte("share"), 10))
	if _, _, err := Decode(piece, [][]byte{[]byte("WRONG")}, nil); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	piece, _ := Encode(buildInput([]byte("share bytes here"), 20))
	// Every region matters: salt, cost byte, nonce, body, and tag.
	for _, pos := range []int{0, saltLen, saltLen + 1, headerLen + 2, len(piece) - 1} {
		bad := append([]byte(nil), piece...)
		bad[pos] ^= 0xFF
		if _, _, err := Decode(bad, [][]byte{[]byte("password")}, nil); err == nil {
			t.Fatalf("tamper at %d not detected", pos)
		}
	}
}

func TestTruncationRejected(t *testing.T) {
	piece, _ := Encode(buildInput([]byte("share"), 5))
	for _, n := range []int{0, 1, MinPieceLen - 1, MinPieceLen, len(piece) - 1} {
		if n > len(piece) {
			continue
		}
		if _, _, err := Decode(piece[:n], [][]byte{[]byte("password")}, nil); err == nil {
			t.Fatalf("truncation to %d not rejected", n)
		}
	}
}

func TestPureSSSManifest(t *testing.T) {
	in := buildInput([]byte("plainshare"), 0)
	in.Encrypted = false
	in.Layers = nil
	piece, _ := Encode(in)
	m, _, err := Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Encrypted {
		t.Fatal("should be pure-sss")
	}
	if len(m.Layers) != 0 {
		t.Fatal("no layers expected")
	}
}

// TestKeylessEnvelope covers the no-password envelope: it opens with no
// passwords, refuses a password, and does not pretend to record a cost.
func TestKeylessEnvelope(t *testing.T) {
	in := buildInput([]byte("keyless share"), 12)
	in.Keyless = true
	in.Encrypted = false
	in.Layers = nil
	in.Passwords = nil
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}

	m, _, err := Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Keyless || m.Encrypted || m.KDFStored {
		t.Fatalf("bad flags: %+v", m)
	}
	if !bytes.Equal(m.Share, []byte("keyless share")) {
		t.Fatal("share mismatch")
	}

	// Offering a password must not open a keyless piece.
	if _, _, err := Decode(piece, [][]byte{[]byte("anything")}, nil); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}

	// Tampering is still detected without a password.
	for _, pos := range []int{0, saltLen, headerLen + 1, len(piece) - 1} {
		bad := append([]byte(nil), piece...)
		bad[pos] ^= 0xFF
		if _, _, err := Decode(bad, nil, nil); err == nil {
			t.Fatalf("tamper at %d not detected", pos)
		}
	}
}

func TestKeylessRejectsPasswords(t *testing.T) {
	in := buildInput([]byte("s"), 0)
	in.Keyless = true
	// Passwords are still set by buildInput, which is a contradiction.
	if _, err := Encode(in); err == nil {
		t.Fatal("keyless with passwords should be rejected")
	}
}

func TestPasswordPieceRequiresPassword(t *testing.T) {
	in := buildInput([]byte("s"), 0)
	in.Passwords = nil
	if _, err := Encode(in); err == nil {
		t.Fatal("a non-keyless piece with no password should be rejected")
	}
}

// TestKeylessIsCheap checks the keyless path performs no password hashing, which
// is what lets combine open such a set without asking anything.
func TestKeylessIsCheap(t *testing.T) {
	in := buildInput([]byte("share"), 0)
	in.Keyless = true
	in.Passwords = nil
	// A cost that would take a noticeable amount of time if it were ever used.
	in.Params = kdf.Params{Memory: 1024 * 1024, Time: 8, Par: 4}
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := Decode(piece, nil, nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("keyless decode took %v; it should not derive a key", elapsed)
	}
}

func TestRejectsBadInput(t *testing.T) {
	in := buildInput([]byte("s"), 0)
	in.SetID = []byte{1, 2, 3}
	if _, err := Encode(in); err == nil {
		t.Fatal("short set id should fail")
	}
	in = buildInput([]byte("s"), 0)
	in.PayloadHash = []byte{1}
	if _, err := Encode(in); err == nil {
		t.Fatal("short hash should fail")
	}
	in = buildInput([]byte("s"), 0)
	in.Serial = 9
	if _, err := Encode(in); err == nil {
		t.Fatal("serial past N should fail")
	}
	in = buildInput([]byte("s"), 0)
	in.Params = kdf.Params{Memory: 19 * 1024, Time: 1, Par: 1}
	if _, err := Encode(in); err == nil {
		t.Fatal("unencodable params should fail")
	}
}

// TestNoPlaintextStructure guards the stealth property: pieces of one set must
// not share bytes at any fixed offset, since that would link them.
func TestNoPlaintextStructure(t *testing.T) {
	share := bytes.Repeat([]byte{0x41}, 200)
	a, err := Encode(buildInput(share, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(buildInput(share, 0))
	if err != nil {
		t.Fatal(err)
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	same := 0
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			same++
		}
	}
	// Two independent random streams agree on about 1/256 of bytes; a shared
	// header would push this far higher.
	if same > n/16 {
		t.Fatalf("pieces share %d of %d bytes, suggesting a fixed header", same, n)
	}
}

// FuzzDecode feeds arbitrary bytes and passwords: it must never panic, only
// return errors.
//
// The cost parameters are pinned to a cheap configuration. Without that, the
// recorded cost byte in random input selects arbitrary Argon2 parameters, and the
// fuzzer would spend its time running the key derivation instead of exploring the
// parser. PeekParams and the exhaustive cost round-trip in the kdf tests cover the
// recorded-cost path.
func FuzzDecode(f *testing.F) {
	piece, _ := Encode(buildInput([]byte("seed share"), 8))
	f.Add(piece, []byte("password"))
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0}, 100), []byte("x"))
	f.Fuzz(func(t *testing.T, data, pw []byte) {
		_, _, _ = Decode(data, [][]byte{pw}, &fast)
		_, _ = PeekParams(data)
	})
}

// TestPeekParams checks the declared cost can be read without deriving a key, so
// callers can warn before an expensive open.
func TestPeekParams(t *testing.T) {
	want := kdf.Params{Memory: 32 * 1024, Time: 4, Par: 2}
	in := buildInput([]byte("share"), 0)
	in.Params = want
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := PeekParams(piece)
	if !ok {
		t.Fatal("PeekParams should succeed on a valid piece")
	}
	if got != want {
		t.Fatalf("peeked %+v, want %+v", got, want)
	}
	if _, ok := PeekParams(piece[:MinPieceLen-1]); ok {
		t.Fatal("PeekParams should reject short input")
	}
	// Any input long enough yields some valid configuration, which is what makes
	// a recorded byte indistinguishable from noise.
	junk := bytes.Repeat([]byte{0xA5}, MinPieceLen)
	p, ok := PeekParams(junk)
	if !ok {
		t.Fatal("PeekParams should accept any sufficiently long input")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("peeked params must always be valid: %v", err)
	}
}

// TestPieceLenMatchesAnEncodedPiece checks the length formula the padding is
// computed from against a real piece, for a range of share lengths and layer
// counts. A drift here would misplace every piece in the wrong size class.
func TestPieceLenMatchesAnEncodedPiece(t *testing.T) {
	for _, layers := range []int{0, 1, 3} {
		descs := make([]cascade.Descriptor, layers)
		for i := range descs {
			descs[i] = cascade.Descriptor{Kind: cascade.Password, SchemeID: 1, Recorded: true}
		}
		for _, shareLen := range []int{1, 64, 1000} {
			for _, padLen := range []int{0, 7, 500} {
				for _, name := range []string{"", "secret.pdf"} {
					piece, err := Encode(EncodeInput{
						SetID: make([]byte, SetIDLen), K: 1, N: 1, Serial: 1,
						PayloadHash: make([]byte, 32), PayloadLen: uint64(shareLen),
						Share: make([]byte, shareLen), PadLen: padLen, Name: name,
						Passwords: [][]byte{[]byte("p")}, Params: fast,
						Layers: descs,
					})
					if err != nil {
						t.Fatal(err)
					}
					if want := PieceLen(shareLen, padLen, layers, len(name)); len(piece) != want {
						t.Fatalf("layers=%d share=%d pad=%d name=%q: piece is %d bytes, PieceLen says %d",
							layers, shareLen, padLen, name, len(piece), want)
					}
				}
			}
		}
	}
}
