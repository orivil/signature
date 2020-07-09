// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package signature

import "encoding/pem"

// Try to decode PEM data, it return source data if if failed
func TryDecodePemData(data []byte) []byte {
	b, src := pem.Decode(data)
	if b != nil {
		return b.Bytes
	} else {
		return src
	}
}
