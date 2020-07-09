// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature

import (
	"crypto"
	"crypto/hmac"
)

type SignMethodHMAC struct {
	Key  []byte
	Hash crypto.Hash
}

func NewSignMethodHMAC(hash crypto.Hash, key []byte) *SignMethodHMAC {
	return &SignMethodHMAC{
		Key:  key,
		Hash: hash,
	}
}

func (sm *SignMethodHMAC) Sign(data []byte) (signature []byte, err error) {
	mac := hmac.New(sm.Hash.New, sm.Key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (sm *SignMethodHMAC) Verify(signature, data []byte) (ok bool, err error) {
	gotSignature, _ := sm.Sign(data)
	return hmac.Equal(gotSignature, signature), nil
}
