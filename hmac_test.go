// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature_test

import (
	"crypto"
	"github.com/orivil/signature"
	"testing"
)

var hmacKey = []byte("private key")

func TestNewSignMethodHMAC(t *testing.T) {
	es := signature.NewSignMethodHMAC(crypto.SHA256, hmacKey)
	testMethod(es, t)
}

// 1565 ns/op
func BenchmarkSignMethodHMAC_Sign(b *testing.B) {
	es := signature.NewSignMethodHMAC(crypto.SHA256, hmacKey)
	var value = []byte("Hello World")
	benchmarkSign(es, value, b)
}

// 1614 ns/op
func BenchmarkSignMethodHMAC_Verify(b *testing.B) {
	es := signature.NewSignMethodHMAC(crypto.SHA256, hmacKey)
	var value = []byte("Hello World")
	sign, err := es.Sign(value)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkVerify(es, sign, value, b)
}
