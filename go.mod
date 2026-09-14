module github.com/quantaureum/qau

go 1.26.6

require (
	github.com/awnumar/memguard v0.23.0
	github.com/cloudflare/circl v1.6.3
	github.com/golang/snappy v1.0.0
	github.com/jchv/go-webview2 v0.0.0-20250406165304-0bcfea011047
	github.com/prometheus/client_golang v1.23.2
	github.com/rs/zerolog v1.34.0
	github.com/spf13/cobra v1.10.2
	go.etcd.io/bbolt v1.4.3
	golang.org/x/crypto v0.56.0
	golang.org/x/term v0.45.0
	golang.org/x/text v0.41.0
)

require (
	github.com/bits-and-blooms/bitset v1.24.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/pprof v0.0.0-20250820193118-f64d9cf942d6 // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/sync v0.22.0 // indirect
)

require (
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/consensys/gnark v0.14.0
	github.com/consensys/gnark-crypto v0.19.2
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.11 // indirect
)

// Core module dependencies:
// - github.com/cloudflare/circl: Post-quantum cryptography (Dilithium signatures)
// - golang.org/x/crypto: Standard cryptographic primitives (scrypt, blake2b, etc.)
// - github.com/spf13/cobra: CLI framework for qauctl and qaud commands
