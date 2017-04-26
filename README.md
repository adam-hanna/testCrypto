# testCrypto
Just playing around and benchmarking go's crypto libraries

Includes: RSA, ECDSA and HMAC

## Benchmarks
Performance on my machine (3 GHz, core 2 duo)
```
BenchmarkRSA-2                       300           5478344 ns/op
BenchmarkSignRSA-2                   300           5374192 ns/op
BenchmarkVerifyRSA-2               10000            128771 ns/op
BenchmarkECDSA-2                    5000            311564 ns/op
BenchmarkSignECDSA-2               20000             83964 ns/op
BenchmarkVerifyECDSA-2             10000            222581 ns/op
BenchmarkHMAC-2                   100000             20429 ns/op
BenchmarkSignHMAC-2               300000              5300 ns/op
BenchmarkVerifyHMAC-2             300000              5475 ns/op
PASS
ok      github.com/adam-hanna/testRSA   17.702s
```