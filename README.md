# golang signature tool

Supported algorithms: `HS256, HS384, HS512, ES256, ES384, ES512, RS256, RS384, RS512`

# Usage
```go
package main

import (
	"fmt"
	"github.com/orivil/signature"
)

func main() {
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

``` 

## Benchmark Test
| Method | Executes | Speed |
| ---- | ----: | ----: |
| BenchmarkSignMethodECDSA_Sign   |          37614  |           31268 ns/op |
| BenchmarkSignMethodECDSA_Verify |          12956  |           91626 ns/op |
| BenchmarkSignMethodHMAC_Sign    |         749995  |            1635 ns/op |
| BenchmarkSignMethodHMAC_Verify  |         857062  |            1664 ns/op |
| BenchmarkSignMethodRSA_Sign     |           2998  |          410491 ns/op |
| BenchmarkSignMethodRSA_Verify   |          42700  |           28246 ns/op |
