# Quantaureum ノード

[English](README.md) | [简体中文](README.zh-CN.md) | 日本語 | [한국어](README.ko-KR.md) | [Español](README.es.md) | [Русский](README.ru-RU.md)

Quantaureum は、しきい値署名によるファイナリティと QVM スマートコントラクト
エンジンを備えた量子安全な Layer 1 ブロックチェーンです。

## 概要

Quantaureum は Go でゼロから実装された耐量子 Layer 1 パブリックチェーンです。
署名には **Dilithium3**（NIST FIPS 204）、鍵交換には **Kyber768**（NIST FIPS 203）
を使用し、独自の **QPOS** コンセンサスと **QTD しきい値署名**でブロックを確定します。

プロジェクトは **2025 年 2 月 28 日**に開始され、暗号、コンセンサス、仮想マシン、
ネットワーク、ストレージ、RPC まで一貫して構築されました。

## 主な機能

| 機能 | 内容 |
| --- | --- |
| 耐量子暗号 | Dilithium3 署名と Kyber768 鍵交換 |
| QTD しきい値署名 | 分散鍵生成とファイナリティ用しきい値署名 |
| QPOS コンセンサス | Proof-of-Stake BFT、乱数、スラッシング、委員会 |
| QVM と QASM | 独自仮想マシンとアセンブリレベルのスマートコントラクト |
| 並列実行 | Block-STM 方式の並列トランザクション実行 |
| データ可用性 | 誤り訂正符号、サンプリング、FRI コミットメント |
| シャーディング | マルチシャード実行とシャード間メッセージング |
| Rollup | 内蔵シーケンサと L1 ブリッジコントラクト |
| クロスチェーン | Merkle 証明に基づくブリッジ設計 |
| マルチシグ | ネイティブ Dilithium マルチシグウォレット |
| ライトクライアント | Verkle 証明による軽量検証 |
| SDK | Go ライブラリと各言語向け SDK |

## アーキテクチャ

```text
L7  rpc/ graphql/            JSON-RPC 2.0、WebSocket、GraphQL
L6  node/ txpool/            ノード制御とトランザクションプール
L5  consensus/ core/         QPOS、QTD finality、ブロック処理
L4  qvm/                     QVM、QASM、JIT、並列実行
L3  p2p/ economics/          認証付きトランスポートとチェーン経済
L2  qaudb/ encoding/ rlp/    ストレージ、ワイヤ形式、シリアライズ
L1  crypto/ types/ common/   Dilithium3、Kyber768、コア型
```

## バージョン情報

ソースリリースのバージョンとプロトコルバージョンはどちらも `1.0.0` で、
`internal/version/version.go` で一元管理されます。リリースビルドでは次の
`ldflags` でバージョン、Git コミット、UTC ビルド時刻を注入できます：

```sh
VERSION=1.0.0
GIT_COMMIT=$(git rev-parse --short HEAD)
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-X github.com/quantaureum/qau/internal/version.Version=$VERSION \
  -X github.com/quantaureum/qau/internal/version.GitCommit=$GIT_COMMIT \
  -X github.com/quantaureum/qau/internal/version.BuildTime=$BUILD_TIME"

go build -trimpath -ldflags "$LDFLAGS" -o bin/qaud ./cmd/qaud
go build -trimpath -ldflags "$LDFLAGS" -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -ldflags "$LDFLAGS" -o bin/qauctl ./cmd/qauctl
go build -trimpath -ldflags "$LDFLAGS" -o bin/qau-visor ./cmd/qau-visor
```

## クイックスタート

`go.mod` に宣言された Go バージョンが必要です。

```sh
git clone https://github.com/Quantaureum/qau.git
cd qau

go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
go build -trimpath -o bin/qau-visor ./cmd/qau-visor
```

開発ノードの起動：

```sh
./bin/qaud --dev --network dev --datadir ./dev-data
```

公開ネットワークの起動：

```sh
./bin/qaud --network mainnet --datadir ./mainnet-data
./bin/qaud --network testnet --datadir ./testnet-data
```

メインネットとテストネットのジェネシス設定、およびメインネットの canonical
bootnode はクライアントに内蔵されています。

## ハードウェアと動作要件

ノードに厳格なハードウェア最低要求はありません。Go のビルドと実行が
可能なマシンなら参加できます。検証済みの参考構成を以下に示します：

| ロール | CPU | メモリ | ディスク | ネットワーク |
| --- | --- | --- | --- | --- |
| フルノード（メインネット/テストネット） | 4 コア | 8 GB | 200 GB SSD | 10 Mbps、静的なパブリック IP 推奨 |
| バリデーター | 8 コア | 16 GB | 500 GB SSD | 100 Mbps、低遅延リンク、静的 IP 必須 |
| 開発網（ローカル） | 2 コア | 4 GB | 10 GB | なし |

注：

- Dilithium3 の署名検証と QTD しきい値署名は CPU 集約型です。
  バリデーター鍵と署名状態はバリデーター上のホストに保存してください。
- 状態はチェーン履歴に伴い増加します。SSD の使用と、データディレクトリの
  空き容量の監視を推奨します。
- Go ツールチェーン：`go.mod` に宣言されたバージョンを使用してください。
- ポート：P2P 聴取アドレスのデフォルトは `0.0.0.0:9000`
  （`listenAddr`）。HTTP JSON-RPC、WebSocket、メトリックスの
  エンドポイントは設定可能です。正確なキーは
  [設定ガイド](docs/CONFIGURATION.md)を参照。

## ネットワーク ID

| ネットワーク | Chain ID / Network ID | 16 進 Chain ID | 用途 |
| --- | ---: | --- | --- |
| メインネット | 1668 | `0x684` | 本番ネットワーク |
| テストネット | 1669 | `0x685` | 公開テストネット |
| 開発用 | 1333 | `0x535` | ローカル開発 |

## リポジトリ構成

```text
cmd/            ノード、CLI、ツール、ベンチマークコマンド
crypto/         Dilithium3、Kyber768、QTD 暗号
types/          ブロック、トランザクション、アドレス、コア型
common/         共有ユーティリティ
encoding/       ワイヤ形式、DAS、消符号化、FRI
rlp/ abi/       シリアライズとコントラクト ABI エンコーディング
qaudb/          ストレージ、状態、ブロックストア、Verkleトライ
consensus/      QPOS、finality、選挙、スラッシング、シャーディング
core/           ブロック生成と検証
qvm/            QVM、QASM、JIT、並列実行
node/           ノード制御と同期
rpc/ graphql/   JSON-RPC、WebSocket、GraphQL API
p2p/            暗号化トランスポート、ディスカバリ、ゴシップ
txpool/ miner/  トランザクションプールとブロック確定
wallet/ economics/ ウォレット、ステーキング、報酬、ガバナンス
rollup/ bridge/ ロールアップとクロスチェーンブリッジ
privacy/ qzkp/  プライバシーとゼロ知識証明
light/ lightclient/ ライトノードと検証コンポーネント
metrics/ log/ tracing/ オブザーバビリティ
contracts/      QASM と Solidity 参照コントラクト
docs/           公開ドキュメント
```

## JSON-RPC API

Ethereum 互換の `eth_chainId`、`eth_blockNumber`、`eth_getBalance`、
`eth_sendRawTransaction`、`eth_call`、`eth_estimateGas` などのメソッドを
サポートします。Quantaureum 固有の API は `qau_` 名前空間を使用します。

## SDK

ノードは Go ライブラリとして直接利用できます。Go、TypeScript、Rust、C++、
Java、Python 用の SDK はこのリポジリの `sdks/` に含まれます。

## テスト

```sh
go test ./...
go test -race ./crypto/... ./consensus/... ./qvm/...
go test ./node -run "TestDefaultGenesis|TestTestnetGenesis|TestBuiltinNetworkGenesisValidation|TestGenesisValidate"
```

## 暗号仕様

| 要素 | アルゴリズム | 規格 | 鍵サイズ | 署名サイズ |
| --- | --- | --- | --- | ---: |
| 署名 | Dilithium3 | NIST FIPS 204 | 公開鍵 1952 バイト / 秘密鍵 4000 バイト | 3293 バイト |
| 鍵交換 | Kyber768 | NIST FIPS 203 | 公開鍵 1184 バイト / 秘密鍵 2400 バイト | 該当なし |
| しきい値署名 | GM-QTD | Quantaureum 設計 | グループ公開鍵 1952 バイト | 3293 バイト |
| ハッシュ | Blake2b-256 / SHA3-256 | RFC 7693 / FIPS 202 | 該当なし | 32 バイト |
| Keystore | AES-256-GCM / scrypt | NIST SP 800-38D / RFC 7914 | 該当なし | 該当なし |

HD ウォレットパス：`m/44'/1668'/0'/0/{index}`。

## ソースリリースの範囲

本リポジトリには、ノードとツールのソースコード、内蔵ネットワーク設定、コントラクト
ソース、依存関係マニフェスト、テストが含まれます。実行時設定、秘密鍵、証明書、
パスワード、デプロイスクリプト、コンテナイメージ、生成ビルド成果物は含まれません。

## ドキュメント

- [デプロイガイド](docs/DEPLOYMENT.md)
- [ネットワークガイド](docs/NETWORK.md)
- [設定ガイド](docs/CONFIGURATION.md)
- [利用ガイド](docs/USAGE.md)

## セキュリティ

秘密鍵、ニーモニック、パスワード、証明書、本番ネットワークトポロジをリポジトリに
コミットしないでください。実行時の秘密情報はソースツリー外の権限が制限された場所で
管理してください。

## コミュニティ

- [Discord](https://discord.com/invite/MSctkBT5j)
- [X (@ldf1570073)](https://x.com/ldf1570073)
- [GitHub](https://github.com/Quantaureum/qau)

## ライセンス

Apache License 2.0。詳細は [LICENSE](LICENSE) を参照してください。
