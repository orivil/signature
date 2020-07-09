// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"github.com/orivil/signature"
	"testing"
)

var ecdsaKey = genECDSAPrivateKey(elliptic.P256())

func TestNewSignMethodECDSA(t *testing.T) {
	es, err := signature.NewSignMethodECDSA(crypto.SHA256, ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	testMethod(es, t)
}

// 31502 ns/op
func BenchmarkSignMethodECDSA_Sign(b *testing.B) {
	es, err := signature.NewSignMethodECDSA(crypto.SHA256, ecdsaKey)
	if err != nil {
		b.Fatal(err)
	}
	var value = []byte("Hello World")
	benchmarkSign(es, value, b)
}

// 94467 ns/op
func BenchmarkSignMethodECDSA_Verify(b *testing.B) {
	es, err := signature.NewSignMethodECDSA(crypto.SHA256, ecdsaKey)
	if err != nil {
		b.Fatal(err)
	}
	var value = []byte("Hello World")
	sign, err := es.Sign(value)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkVerify(es, sign, value, b)
}

func testMethod(m signature.SignMethod, t *testing.T) {
	var value = []byte("Hello World")
	sign, err := m.Sign(value)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := m.Verify(sign, value)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid failed")
	}
	value = []byte("Hell World")
	ok, err = m.Verify(sign, value)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("valid failed")
	}
}

func benchmarkSign(m signature.SignMethod, value []byte, b *testing.B) {
	var err error
	for i := 0; i < b.N; i++ {
		_, err = m.Sign(value)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkVerify(m signature.SignMethod, sign, value []byte, b *testing.B) {
	for i := 0; i < b.N; i++ {
		ok, err := m.Verify(sign, value)
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Fatal("verify failed")
		}
	}
}

func genECDSAPrivateKey(curve elliptic.Curve) []byte {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	k, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return k
}
