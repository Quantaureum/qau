# Quantaureum SDKs

Version 1.0.0

This directory contains the officially supported Quantaureum SDKs. All SDKs are
part of this repository and can be built from source without operational
configuration or key material.

| Language | Path | Build entry point |
| --- | --- | --- |
| Go | [`go-sdk/`](go-sdk/) | `go build ./...` |
| TypeScript | [`ts-sdk/`](ts-sdk/) | `npm install && npm run build` |
| Rust | [`rust-sdk/`](rust-sdk/) | `cargo build` |
| Java | [`java-sdk/`](java-sdk/) | `mvn package` |
| Python | [`python-sdk/`](python-sdk/) | `python -m build` |
| C++ | [`cpp-sdk/`](cpp-sdk/) | `cmake -S . -B build && cmake --build build` |

Each SDK has its own README with API examples and language-specific build
instructions. The SDKs communicate with a node through its public JSON-RPC
endpoint; no SDK source file contains node keys, wallet keys, server
credentials, or deployment topology.
