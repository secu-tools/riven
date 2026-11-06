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

func buildInput(share []byte) EncodeInput {
	setID := make([]byte, setIDLen)
	rand.Read(setID)
	return EncodeInput{
		Details: Details{
			K:          3,
			N:          5,
			Encrypted:  true,
			AlgoStored: true,
			KDFStored:  true,
			Layers:     []cascade.Descriptor{{Kind: cascade.Password, SchemeID: 1, Recorded: true}},
			Params:     fast,
		},
		SetID:       setID,
		Serial:      2,
		PayloadHash: Hash(share),
		Share:       share,
		Passwords:   [][]byte{[]byte("password")},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	share := []byte("this is a shamir share of some payload")
	piece, err := Encode(buildInput(share))
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
	in := buildInput([]byte("share bytes for creator test"))
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
	bare := buildInput([]byte("no creator recorded"))
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
	in := buildInput([]byte("share"))
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
		in := buildInput([]byte("share"))
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
	in := buildInput([]byte("share bytes"))
	in.KDFStored = false
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
	in := buildInput([]byte("share"))
	in.AlgoStored = false
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
	piece, _ := Encode(buildInput([]byte("share")))
	if _, _, err := Decode(piece, [][]byte{[]byte("WRONG")}, nil); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	piece, _ := Encode(buildInput([]byte("share bytes here")))
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
	piece, _ := Encode(buildInput([]byte("share")))
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
	in := buildInput([]byte("plainshare"))
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
	in := buildInput([]byte("keyless share"))
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

	// Passwords may be meant for the cascade behind a keyless envelope, so
	// offering one still opens the piece, and with the same manifest.
	again, _, err := Decode(piece, [][]byte{[]byte("anything")}, nil)
	if err != nil || !again.Keyless {
		t.Fatalf("a keyless piece did not open with a password offered: %v", err)
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
	in := buildInput([]byte("s"))
	in.Keyless = true
	// Passwords are still set by buildInput, which is a contradiction.
	if _, err := Encode(in); err == nil {
		t.Fatal("keyless with passwords should be rejected")
	}
}

func TestPasswordPieceRequiresPassword(t *testing.T) {
	in := buildInput([]byte("s"))
	in.Passwords = nil
	if _, err := Encode(in); err == nil {
		t.Fatal("a non-keyless piece with no password should be rejected")
	}
}

// TestKeylessIsCheap checks the keyless path performs no password hashing, which
// is what lets combine open such a set without asking anything.
func TestKeylessIsCheap(t *testing.T) {
	in := buildInput([]byte("share"))
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
	in := buildInput([]byte("s"))
	in.SetID = []byte{1, 2, 3}
	if _, err := Encode(in); err == nil {
		t.Fatal("short set id should fail")
	}
	in = buildInput([]byte("s"))
	in.PayloadHash = []byte{1}
	if _, err := Encode(in); err == nil {
		t.Fatal("short hash should fail")
	}
	in = buildInput([]byte("s"))
	in.Serial = 9
	if _, err := Encode(in); err == nil {
		t.Fatal("serial past N should fail")
	}
	in = buildInput([]byte("s"))
	in.Params = kdf.Params{Memory: 19 * 1024, Time: 1, Par: 1}
	if _, err := Encode(in); err == nil {
		t.Fatal("unencodable params should fail")
	}
}

// TestNoPlaintextStructure guards the stealth property: pieces of one set must
// not share bytes at any fixed offset, since that would link them.
func TestNoPlaintextStructure(t *testing.T) {
	share := bytes.Repeat([]byte{0x41}, 200)
	a, err := Encode(buildInput(share))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(buildInput(share))
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
	piece, _ := Encode(buildInput([]byte("seed share")))
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
	in := buildInput([]byte("share"))
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
// counts, with and without a fragment and hidden details. A drift here would
// misplace every piece in the wrong size class.
func TestPieceLenMatchesAnEncodedPiece(t *testing.T) {
	for _, layers := range []int{0, 1, 3} {
		descs := make([]cascade.Descriptor, layers)
		for i := range descs {
			descs[i] = cascade.Descriptor{Kind: cascade.Password, SchemeID: 1, Recorded: true}
		}
		for _, shareLen := range []int{1, 64, 1000} {
			for _, name := range []string{"", "secret.pdf"} {
				for _, fragLen := range []int{0, 1, 300} {
					for _, detailsLen := range []int{0, 90} {
						in := EncodeInput{
							Details: Details{
								K:      1,
								N:      1,
								Name:   name,
								Params: fast,
								Layers: descs,
							},
							SetID:        make([]byte, SetIDLen),
							Serial:       1,
							PayloadHash:  make([]byte, 32),
							Share:        make([]byte, shareLen),
							Passwords:    [][]byte{[]byte("p")},
							Fragment:     make([]byte, fragLen),
							DetailsShare: make([]byte, detailsLen),
						}
						shape := Shape{Share: shareLen, Layers: layers, Meta: len(name), Fragment: fragLen}
						if detailsLen > 0 {
							in.Keyless, in.Passwords = true, nil
							shape = Shape{Share: shareLen, Fragment: fragLen, Details: detailsLen}
						}
						piece, err := Encode(in)
						if err != nil {
							t.Fatal(err)
						}
						if want := PieceLen(shape); len(piece) != want {
							t.Fatalf("layers=%d share=%d name=%q fragment=%d details=%d: piece is %d bytes, PieceLen says %d",
								layers, shareLen, name, fragLen, detailsLen, len(piece), want)
						}
					}
				}
			}
		}
	}
}

// TestHiddenDetailsShowNothing checks a manifest with hidden details carries none
// of them: whatever the input says about the set, the piece opens with the public
// key to a set id, a hash, and the shares, and nothing that names the set.
func TestHiddenDetailsShowNothing(t *testing.T) {
	in := buildInput([]byte("a share"))
	in.Keyless, in.Passwords, in.Stretched = true, nil, true
	in.Name, in.CreatorVersion, in.CreatorCommit = "wallet-seed.txt", "9.9.9", "feedface"
	in.DetailsShare = []byte("the details share")
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	m, params, err := Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Hidden || !m.Keyless || m.K != 0 || m.N != 0 || m.Serial != 0 || len(m.Layers) != 0 ||
		m.Name != "" || m.CreatorVersion != "" || m.CreatorCommit != "" ||
		m.Encrypted || m.Hybrid || m.AlgoStored || m.KDFStored || params != (kdf.Params{}) {
		t.Fatalf("a hidden manifest shows details: %+v, params %+v", m, params)
	}
	if !bytes.Equal(m.DetailsShare, in.DetailsShare) || !bytes.Equal(m.Share, in.Share) {
		t.Fatal("the shares did not survive")
	}
	if p, _ := PeekParams(piece); p == fast {
		// The byte is random, so this is a one in 256 coincidence at worst.
		t.Log("the cost byte happens to decode to the real cost")
	}
}

// TestHiddenDetailsNeedTheKeylessEnvelope refuses hidden details behind a
// password, which would bring back the guessing they exist to prevent.
func TestHiddenDetailsNeedTheKeylessEnvelope(t *testing.T) {
	in := buildInput([]byte("s"))
	in.DetailsShare = []byte("details")
	if _, err := Encode(in); err == nil {
		t.Fatal("hidden details behind a password envelope were accepted")
	}
}

// TestPublicDetailsWithAPassword covers a password set sealed with the keyless
// envelope: it opens with no password at all, still says it is encrypted, and
// keeps its recorded cost readable, since the cascade needs it.
func TestPublicDetailsWithAPassword(t *testing.T) {
	in := buildInput([]byte("share"))
	in.Keyless, in.Passwords, in.Stretched = true, nil, true
	in.Params = kdf.Params{Memory: 32 * 1024, Time: 2, Par: 2}
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	m, params, err := Decode(piece, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Keyless || !m.Encrypted || !m.KDFStored || m.K != 3 || len(m.Layers) != 1 {
		t.Fatalf("public details lost: %+v", m)
	}
	if params != in.Params {
		t.Fatalf("recorded cost %+v, want %+v", params, in.Params)
	}
	override := fast
	if _, got, _ := Decode(piece, nil, &override); got != fast {
		t.Fatalf("an override was not used: %+v", got)
	}
}

func TestFragmentRoundTrip(t *testing.T) {
	in := buildInput([]byte("share"))
	in.Fragment = []byte{7, 1, 2, 3}
	piece, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Compact || !bytes.Equal(m.Fragment, in.Fragment) {
		t.Fatalf("fragment lost: %+v", m)
	}
	// The flag follows the fragment, so a piece without one is not compact.
	in.Fragment = nil
	if piece, err = Encode(in); err != nil {
		t.Fatal(err)
	}
	if m, _, err = Decode(piece, [][]byte{[]byte("password")}, nil); err != nil || m.Compact {
		t.Fatalf("a piece without a fragment: %v, compact %v", err, m != nil && m.Compact)
	}
}

// TestManifestChecks feeds parseManifest bodies that contradict themselves, the
// way a crafted keyless piece could: each must be refused rather than read.
func TestManifestChecks(t *testing.T) {
	base := buildInput([]byte("share"))
	base.Keyless, base.Passwords = true, nil
	good := base.manifest()
	if _, err := parseManifest(good); err != nil {
		t.Fatalf("a good manifest was refused: %v", err)
	}
	flagsAt := 2 + setIDLen + 3
	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	cases := map[string][]byte{
		"keyless and sealed":    mutate(func(b []byte) { b[flagsAt] |= flagSealed }),
		"compact, no fragment":  mutate(func(b []byte) { b[flagsAt] |= flagCompact }),
		"hidden, details shown": mutate(func(b []byte) { b[flagsAt] |= flagHidden }),
		"serial past n":         mutate(func(b []byte) { b[flagsAt-1] = 9 }),
		"trailing bytes":        append(append([]byte(nil), good...), 0),
		"wrong version":         mutate(func(b []byte) { b[1] = 9 }),
	}
	for name, body := range cases {
		if _, err := parseManifest(body); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// TestWrapInPlace checks Wrap finishes shared bytes around a payload already in
// place, matching WrapPayload, and refuses a buffer that leaves too little fill.
func TestWrapInPlace(t *testing.T) {
	payload := []byte("already in place")
	shared := make([]byte, SharedLen(len(payload), MinFill+5))
	copy(shared[PayloadAt:], payload)
	hash, err := Wrap(shared, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := UnwrapPayload(shared, hash)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("unwrapped %q, %v", got, ok)
	}
	if _, err := Wrap(make([]byte, SharedLen(len(payload), MinFill-1)), len(payload)); err == nil {
		t.Fatal("a buffer with too little fill was wrapped")
	}
	if _, err := Wrap(make([]byte, 64), -1); err == nil {
		t.Fatal("a negative payload length was wrapped")
	}
}

// TestWipeClearsTheShare checks the share a decoded manifest carries is cleared
// by Wipe, and that what describes the piece stays readable.
func TestWipeClearsTheShare(t *testing.T) {
	share := []byte("a share that must not linger")
	piece, err := Encode(buildInput(share))
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := Decode(piece, [][]byte{[]byte("password")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := m.Share
	m.Wipe()
	if m.Share != nil || !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("the share survived Wipe")
	}
	if m.K != 3 || len(m.SetID) != SetIDLen {
		t.Fatalf("Wipe cleared the details: %+v", m)
	}
}
