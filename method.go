// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature

import (
	"crypto"
)

const (
	HS256 Algorithm = iota
	HS384
	HS512
	ES256
	ES384
	ES512
	RS256
	RS384
	RS512
)

type Algorithm int

var algorithms = map[Algorithm]string{
	HS256: "HS256",
	HS384: "HS384",
	HS512: "HS512",
	ES256: "ES256",
	ES384: "ES384",
	ES512: "ES512",
	RS256: "RS256",
	RS384: "RS384",
	RS512: "RS512",
}

func (a Algorithm) Hash() crypto.Hash {
	name := a.String()
	switch name[2:] {
	case "256":
		return crypto.SHA256
	case "384":
		return crypto.SHA384
	case "512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func (a Algorithm) Type() SignType {
	name := a.String()
	switch name[0:2] {
	case "HS":
		return HMAC
	case "RS":
		return RSA
	case "ES":
		return ECDSA
	default:
		return HMAC
	}
}

func (a Algorithm) String() string {
	name := algorithms[a]
	if name == "" {
		name = algorithms[HS256]
	}
	return name
}

const (
	HMAC SignType = iota
	ECDSA
	RSA
)

type SignType int

type SignMethod interface {
	Sign(data []byte) (signature []byte, err error)
	Verify(signature, data []byte) (ok bool, err error)
}

func NewSignMethod(algorithm Algorithm, privateKey []byte) (SignMethod, error) {
	t, h := algorithm.Type(), algorithm.Hash()
	switch t {
	case HMAC:
		return NewSignMethodHMAC(h, privateKey), nil
	case ECDSA:
		return NewSignMethodECDSA(h, privateKey, nil)
	case RSA:
		return NewSignMethodRSA(h, privateKey)
	default:
		return NewSignMethodHMAC(crypto.SHA256, privateKey), nil
	}
}
