// Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/unicode/norm"
)

// These tests are the end-to-end promise of internal/password: a file split with
// a password entered one way must reconstruct when the same password is re-entered
// in a different Unicode composition or a different character encoding. Without
// canonicalization the derived key would differ and the data would be lost.

// TestI18nPassword_ComposedVsDecomposed splits with a precomposed (NFC) password
// and combines with the visually identical decomposed (NFD) form.
func TestI18nPassword_ComposedVsDecomposed(t *testing.T) {
	input := []byte("data protected by an accented password")
	nfc := norm.NFC.String("Contraseña-Café-Über") // precomposed
	nfd := norm.NFD.String(nfc)                    // combining marks
	if nfc == nfd {
		t.Fatal("test bug: NFC and NFD forms are identical")
	}

	pieces := mustSplit(t, input, SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte(nfc)}},
	})

	got, err := Combine(pieces[:2], OpenOptions{Passwords: [][]byte{[]byte(nfd)}})
	if err != nil {
		t.Fatalf("combine with decomposed password: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("recovered data does not match original")
	}
}

// TestI18nPassword_Utf8VsGB18030 splits with a UTF-8 Chinese password and
// combines with the same characters encoded as GB18030, the stated failure case.
func TestI18nPassword_Utf8VsGB18030(t *testing.T) {
	input := []byte("secret guarded by a chinese password")
	utf8pw := "中文密码口令测试" // "Chinese password passphrase test"
	gbpw, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(utf8pw))
	if err != nil {
		t.Fatalf("encode GB18030: %v", err)
	}

	pieces := mustSplit(t, input, SplitOptions{
		N: 5, K: 3,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte(utf8pw)}},
	})

	got, err := Combine(pieces[:3], OpenOptions{Passwords: [][]byte{gbpw}})
	if err != nil {
		t.Fatalf("combine with GB18030 password: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("recovered data does not match original")
	}
}

// TestI18nPassword_MultiLayerMixedForms stacks two password layers and re-enters
// each in a different form than it was split with.
func TestI18nPassword_MultiLayerMixedForms(t *testing.T) {
	input := []byte("two layers, two scripts")
	outer := "café"     // Latin, will re-enter as NFD
	inner := "日本語パスワード" // Japanese, will re-enter as GB18030 bytes

	pieces := mustSplit(t, input, SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{
			{Kind: PasswordLayer, Password: []byte(norm.NFC.String(outer))},
			{Kind: PasswordLayer, Password: []byte(inner)},
		},
	})

	innerGB, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(inner))
	if err != nil {
		t.Fatalf("encode inner GB18030: %v", err)
	}
	open := OpenOptions{Passwords: [][]byte{
		[]byte(norm.NFD.String(outer)),
		innerGB,
	}}

	got, err := Combine(pieces[:2], open)
	if err != nil {
		t.Fatalf("combine with mixed-form passwords: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("recovered data does not match original")
	}
}

// TestI18nPassword_InfoAgrees checks single-piece inspection also opens under an
// alternate form, since info derives the envelope key the same way.
func TestI18nPassword_InfoAgrees(t *testing.T) {
	input := []byte("inspect me")
	utf8pw := "비밀번호-key" // Korean + ASCII
	pieces := mustSplit(t, input, SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte(norm.NFC.String(utf8pw))}},
	})

	info, err := Info(pieces[0], OpenOptions{Passwords: [][]byte{[]byte(norm.NFD.String(utf8pw))}})
	if err != nil {
		t.Fatalf("info with decomposed password: %v", err)
	}
	if info.K != 2 || info.N != 3 {
		t.Fatalf("info reported k=%d n=%d, want 2/3", info.K, info.N)
	}
}

// TestI18nPassword_WrongPasswordStillFails is the negative control: a genuinely
// different password must not open the set, so canonicalization has not widened
// what counts as correct.
func TestI18nPassword_WrongPasswordStillFails(t *testing.T) {
	input := []byte("do not open")
	pieces := mustSplit(t, input, SplitOptions{
		N: 3, K: 2,
		Layers: []LayerSpec{{Kind: PasswordLayer, Password: []byte("中文密码")}},
	})
	// Different characters, not merely a different encoding of the same ones.
	if _, err := Combine(pieces[:2], OpenOptions{Passwords: [][]byte{[]byte("中文密馬")}}); err == nil {
		t.Fatal("a different password must not reconstruct")
	}
}
