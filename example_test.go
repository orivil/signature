// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature_test

import (
	"fmt"
	"github.com/orivil/signature"
)

func ExampleNewSignMethod() {
	var privateKey = []byte("secret key")

	// Supported algorithms: HS256, HS384, HS512, ES256, ES384, ES512, RS256, RS384, RS512
	var algorithm = signature.HS256
	method, err := signature.NewSignMethod(algorithm, privateKey)
	if err != nil {
		panic(err)
	}
	var v1 = []byte("Hello World!")
	var sign []byte

	// Get signature
	sign, err = method.Sign(v1)
	if err != nil {
		panic(err)
	}

	var v2 = []byte("Hell World!")
	var ok bool

	// Verify data
	ok, err = method.Verify(sign, v2)
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	// Output:
	// false
}
