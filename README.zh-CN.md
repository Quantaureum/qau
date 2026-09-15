# Quantaureum 节点

[English](README.md) | 简体中文 | [日本語](README.ja-JP.md) | [한국어](README.ko-KR.md) | [Español](README.es.md) | [Русский](README.ru-RU.md)

Quantaureum 是一条量子安全的 Layer 1 区块链，具备门限签名终局性和 QVM 智能合约引擎。

## 概览

Quantaureum 是使用 Go 从零实现的抗量子 Layer 1 公链。签名使用
**Dilithium3**（NIST FIPS 204），密钥交换使用 **Kyber768**（NIST FIPS 203），
并采用自定义 **QPOS** 共识与 **QTD 门限签名**完成区块终局性。

项目由作者于 **2025 年 2 月 28 日**启动，从密码学、共识、虚拟机、网络、存储到
RPC 逐步完成。

## 核心特性

| 特性 | 说明 |
| --- | --- |
| 抗量子密码学 | Dilithium3 签名与 Kyber768 密钥交换 |
| QTD 门限签名 | 分布式密钥生成与终局性门限签名 |
| QPOS 共识 | 权益证明 BFT、可验证随机性、罚没与委员会 |
| QVM 与 QASM | 自定义虚拟机与汇编级智能合约 |
| 并行执行 | Block-STM 风格的并行交易执行 |
| 数据可用性 | 纠删码、数据可用性采样与 FRI 承诺 |
| 分片 | 多分片执行与跨分片消息 |
| Rollup 支持 | 内置排序器与 L1 桥合约 |
| 跨链桥 | 基于 Merkle 证明的桥接设计 |
| 多签钱包 | 原生 Dilithium 多签钱包 |
| 轻客户端 | 基于 Verkle 证明的轻验证 |
| SDK | Go 库及 Go、TypeScript、Rust、C++、Java、Python SDK |

## 架构

```text
L7  rpc/ graphql/            JSON-RPC 2.0、WebSocket 与 GraphQL
L6  node/ txpool/            节点编排与交易池
L5  consensus/ core/         QPOS、QTD 终局性与区块处理
L4  qvm/                     QVM、QASM、JIT 与并行执行
L3  p2p/ economics/          认证传输与链上经济
L2  qaudb/ encoding/ rlp/    存储、线路格式与序列化
L1  crypto/ types/ common/   Dilithium3、Kyber768 与核心类型
```

## 版本元数据

源码发布版本为 `1.0.0`，协议版本为 `1.0.0`，二者统一定义在
`internal/version/version.go`。发布构建可注入软件版本、Git 提交号和 UTC 构建时间：

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

## 快速开始

项目要求使用 `go.mod` 声明的 Go 版本。

```sh
git clone https://github.com/Quantaureum/qau.git
cd qau

go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
go build -trimpath -o bin/qau-visor ./cmd/qau-visor
```

Windows 上如需显式可执行文件名，请为输出路径添加 `.exe` 后缀。

启动开发节点：

```sh
./bin/qaud --dev --network dev --datadir ./dev-data
```

启动公共网络节点：

```sh
./bin/qaud --network mainnet --datadir ./mainnet-data
./bin/qaud --network testnet --datadir ./testnet-data
```

主网和测试网创世配置以及 canonical bootnode 记录已内置在客户端中。创世哈希
校验与接入确认见网络指南。

## 硬件与运行要求

节点没有严格的硬件下限——任何能编译运行 Go 的机器都可以加入。下表列出
经过验证的参考配置：

| 角色 | CPU | 内存 | 磁盘 | 网络 |
| --- | --- | --- | --- | --- |
| 全节点（主网/测试网） | 4 核 | 8 GB | 200 GB SSD | 10 Mbps，建议静态公网 IP |
| 验证节点（Validator） | 8 核 | 16 GB | 500 GB SSD | 100 Mbps，低延迟链路，必须静态 IP |
| 开发网（本地） | 2 核 | 4 GB | 10 GB | 无 |

说明：

- Dilithium3 签名验证与 QTD 门限签名计算均为 CPU 密集型；验证者密钥
  与签名状态必须保存在验证节点主机上。
- 状态随链历史增长；建议使用 SSD 并监控数据目录剩余空间。
- Go 工具链：使用 `go.mod` 中声明的版本。
- 端口：P2P 监听地址默认 `0.0.0.0:9000`（`listenAddr`）；HTTP JSON-RPC、
  WebSocket 与监控端点均可配置，详见[配置指南](docs/CONFIGURATION.md)。

## 网络 ID

| 网络 | Chain ID / Network ID | 十六进制 Chain ID | 用途 |
| --- | ---: | --- | --- |
| 主网 | 1668 | `0x684` | 生产网络 |
| 测试网 | 1669 | `0x685` | 公共测试网络 |
| 开发网 | 1333 | `0x535` | 本地开发 |

## 仓库结构

```text
cmd/            节点、CLI、工具与基准测试命令
crypto/         Dilithium3、Kyber768 与 QTD 密码学
types/          区块、交易、地址与核心类型
common/         共享工具
encoding/       线路格式、DAS、纠删码与 FRI
rlp/ abi/       序列化与合约 ABI 编码
qaudb/          存储、状态、区块库与 Verkle 树
consensus/      QPOS、终局性、选举、罚没与分片
core/           区块构建与验证
qvm/            QVM、QASM、JIT 与并行执行
node/           节点编排与同步
rpc/ graphql/   JSON-RPC、WebSocket 与 GraphQL API
p2p/            加密传输、节点发现与 gossip
txpool/ miner/  交易池与区块封装
wallet/ economics/ 钱包、质押、奖励与治理
rollup/ bridge/ Rollup 与跨链桥组件
privacy/ qzkp/  隐私与零知识证明组件
light/ lightclient/ 轻节点与验证组件
metrics/ log/ tracing/ 可观测性
contracts/      QASM 与 Solidity 源码示例
docs/           部署、网络、配置与使用文档
```

## JSON-RPC API

节点支持 Ethereum 兼容的 JSON-RPC 方法，例如 `eth_chainId`、
`eth_blockNumber`、`eth_getBalance`、`eth_getTransactionByHash`、
`eth_sendRawTransaction`、`eth_call` 和 `eth_estimateGas`。

Quantaureum 专属方法使用 `qau_` 命名空间，包括：

| 类别 | 方法 |
| --- | --- |
| 共识 | `qau_qposStatus`、`qau_getStake`、`qau_getStakingStats` |
| TSS / QTD | `qau_tss_status`、`qau_tss_getPublicKey` |
| 量子签名 | `qau_signQuantumTransaction`、`qau_verifyQuantumTransaction` |
| 多签 | `qau_isMultisigWallet`、`qau_getMultisigWallet` |
| 质押 | `qau_getUserStakes`、`qau_getPendingRewards` |
| 账户抽象 | `qau_supportedEntryPoints` |

## SDK

节点可以直接作为 Go 库导入：

```go
import (
    "github.com/quantaureum/qau/crypto"
    "github.com/quantaureum/qau/common"
    "github.com/quantaureum/qau/types"
)
```

独立 SDK 已包含在本仓库：

| 语言 | 路径 | 状态 |
| --- | --- | --- |
| Go | [`sdks/go-sdk`](sdks/go-sdk) | 已包含 |
| TypeScript | [`sdks/ts-sdk`](sdks/ts-sdk) | 已包含 |
| Rust | [`sdks/rust-sdk`](sdks/rust-sdk) | 已包含 |
| C++ | [`sdks/cpp-sdk`](sdks/cpp-sdk) | 已包含 |
| Java | [`sdks/java-sdk`](sdks/java-sdk) | 已包含 |
| Python | [`sdks/python-sdk`](sdks/python-sdk) | 已包含 |

## 测试

```sh
go test ./...
go test -race ./crypto/... ./consensus/... ./qvm/...
go test ./node -run "TestDefaultGenesis|TestTestnetGenesis|TestBuiltinNetworkGenesisValidation|TestGenesisValidate"
```

## 密码学规格

| 原语 | 算法 | 标准 | 密钥长度 | 签名长度 |
| --- | --- | --- | --- | ---: |
| 签名 | Dilithium3 | NIST FIPS 204 | 公钥 1952 字节 / 私钥 4000 字节 | 3293 字节 |
| 密钥交换 | Kyber768 | NIST FIPS 203 | 公钥 1184 字节 / 私钥 2400 字节 | 不适用 |
| 门限签名 | GM-QTD | Quantaureum 设计 | 组公钥 1952 字节 | 3293 字节 |
| 哈希 | Blake2b-256 / SHA3-256 | RFC 7693 / FIPS 202 | 不适用 | 32 字节 |
| Keystore | AES-256-GCM 与 scrypt | NIST SP 800-38D / RFC 7914 | 不适用 | 不适用 |

HD 钱包路径：`m/44'/1668'/0'/0/{index}`。

## 源码发布范围

包含：

- Go 节点、共识、密码学、网络、RPC、数据库与工具源码
- 内置公共主网、测试网预设与创世配置
- Solidity 与 QASM 源码
- 可复现依赖解析所需的 Go module 清单
- 测试套件所需的测试与确定性测试数据

不包含：

- 运行时配置文件与外部引导节点记录
- 私钥、证书、密码文件及其他敏感信息
- 部署脚本、容器镜像与生成构建产物

运维人员应在源码目录之外提供运行时配置、数据目录、密钥以及任何未内置的授权
引导节点。

## 文档

- [部署指南](docs/DEPLOYMENT.md)
- [网络指南](docs/NETWORK.md)
- [配置指南](docs/CONFIGURATION.md)
- [使用指南](docs/USAGE.md)

## 安全说明

不要向本仓库提交私钥、助记词、密码、证书或生产网络拓扑。运行时敏感信息应保存在
专用密钥管理系统或源码目录之外、权限受限的文件中。

## 社区

- [Discord](https://discord.com/invite/MSctkBT5j)
- [X (@ldf1570073)](https://x.com/ldf1570073)
- [GitHub](https://github.com/Quantaureum/qau)

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE)。
