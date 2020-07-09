// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

type SignMethodRSA struct {
	Key  *rsa.PrivateKey
	Hash crypto.Hash
}

func NewSignMethodRSA(hash crypto.Hash, privateKey []byte) (*SignMethodRSA, error) {
	src := TryDecodePemData(privateKey)
	pk, err := x509.ParsePKCS1PrivateKey(src)
	if err != nil {
		return nil, err
	}
	return &SignMethodRSA{
		Key:  pk,
		Hash: hash,
	}, nil
}

func (h *SignMethodRSA) Sign(data []byte) (signature []byte, err error) {
	mac := h.Hash.New()
	mac.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, h.Key, h.Hash, mac.Sum(nil))
}

func (h *SignMethodRSA) Verify(signature, data []byte) (ok bool, err error) {
	mac := h.Hash.New()
	mac.Write(data)
	err = rsa.VerifyPKCS1v15(&h.Key.PublicKey, h.Hash, mac.Sum(nil), signature)
	if err != nil {
		if err == rsa.ErrVerification {
			err = nil
		}
		return false, err
	}
	return true, nil
}
