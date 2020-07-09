// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/orivil/signature"
	"testing"
)

var rsaKey = genRSAPrivateKey(1024)

func TestNewSignMethodRSA(t *testing.T) {
	es, err := signature.NewSignMethodRSA(crypto.SHA256, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	testMethod(es, t)
}

// 401011 ns/op
func BenchmarkSignMethodRSA_Sign(b *testing.B) {
	es, err := signature.NewSignMethodRSA(crypto.SHA256, rsaKey)
	if err != nil {
		b.Fatal(err)
	}
	var value = []byte("Hello World")
	benchmarkSign(es, value, b)
}

// 26649 ns/op
func BenchmarkSignMethodRSA_Verify(b *testing.B) {
	es, err := signature.NewSignMethodRSA(crypto.SHA256, rsaKey)
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

func genRSAPrivateKey(bits int) []byte {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return x509.MarshalPKCS1PrivateKey(key)
}
