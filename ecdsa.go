// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"math/big"
)

type SignMethodECDSA struct {
	Key  *ecdsa.PrivateKey
	Hash crypto.Hash
	// 编码签名, 可自定义该方法
	MarshalBigInt func(r, s *big.Int) (signature []byte, err error)
	// 解码签名, 可自定义该方法
	UnmarshalBigInt func(signature []byte) (r, s *big.Int, err error)
}

func NewSignMethodECDSA(hash crypto.Hash, privateKey []byte) (*SignMethodECDSA, error) {
	src := TryDecodePemData(privateKey)
	pk, err := x509.ParseECPrivateKey(src)
	if err != nil {
		return nil, err
	}
	return &SignMethodECDSA{
		Key:  pk,
		Hash: hash,
		MarshalBigInt: func(r, s *big.Int) ([]byte, error) {
			return json.Marshal(ecdsaSignature{R: r.Bytes(), S: s.Bytes()})
		},
		UnmarshalBigInt: func(signature []byte) (r, s *big.Int, err error) {
			sig := &ecdsaSignature{}
			err = json.Unmarshal(signature, sig)
			if err != nil {
				return nil, nil, err
			}
			r = big.NewInt(0).SetBytes(sig.R)
			s = big.NewInt(0).SetBytes(sig.S)
			return
		},
	}, nil
}

func (h *SignMethodECDSA) Sign(data []byte) (signature []byte, err error) {
	mac := h.Hash.New()
	mac.Write(data)
	var (
		r, s *big.Int
	)
	r, s, err = ecdsa.Sign(rand.Reader, h.Key, mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return h.MarshalBigInt(r, s)
}

type ecdsaSignature struct {
	R, S []byte
}

func (h *SignMethodECDSA) Verify(signature, data []byte) (ok bool, err error) {
	mac := h.Hash.New()
	mac.Write(data)
	var r, s *big.Int
	r, s, err = h.UnmarshalBigInt(signature)
	if err != nil {
		return false, err
	}
	return ecdsa.Verify(&h.Key.PublicKey, mac.Sum(nil), r, s), nil
}
