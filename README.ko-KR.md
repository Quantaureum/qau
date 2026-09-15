# Quantaureum 노드

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja-JP.md) | 한국어 | [Español](README.es.md) | [Русский](README.ru-RU.md)

Quantaureum은 임계값 서명 확정성과 QVM 스마트 컨트랙트 엔진을 갖춘 양자 안전
Layer 1 블록체인입니다.

## 개요

Quantaureum은 Go로 처음부터 구현된 내양자 Layer 1 퍼블릭 블록체인입니다.
서명에는 **Dilithium3**(NIST FIPS 204), 키 교환에는 **Kyber768**(NIST FIPS 203)을
사용하며, 자체 **QPOS** 합의와 **QTD 임계값 서명**으로 블록을 확정합니다.

프로젝트는 **2025년 2월 28일**에 시작되었으며, 암호학, 합의, 가상 머신, 네트워크,
저장소, RPC까지 전체 스택을 직접 구축했습니다.

## 주요 기능

| 기능 | 설명 |
| --- | --- |
| 내양자 암호학 | Dilithium3 서명과 Kyber768 키 교환 |
| QTD 임계값 서명 | 분산 키 생성과 확정성용 임계값 서명 |
| QPOS 합의 | 지분 증명 BFT, 검증 가능한 무작위성, 슬래싱, 위원회 |
| QVM과 QASM | 자체 가상 머신과 어셈블리 수준 스마트 컨트랙트 |
| 병렬 실행 | Block-STM 방식 병렬 트랜잭션 실행 |
| 데이터 가용성 | 부호화, 샘플링, FRI 커밋먼트 |
| 샤딩 | 다중 샤드 실행과 샤드 간 메시징 |
| Rollup | 내장 시퀀서와 L1 브리지 컨트랙트 |
| 크로스체인 | Merkle 증명 기반 브리지 설계 |
| 멀티시그 | 네이티브 Dilithium 멀티시그 지갑 |
| 라이트 클라이언트 | Verkle 증명 기반 경량 검증 |
| SDK | Go 라이브러리와 주요 언어 SDK |

## 아키텍처

```text
L7  rpc/ graphql/            JSON-RPC 2.0, WebSocket, GraphQL
L6  node/ txpool/            노드 오케스트레이션과 트랜잭션 풀
L5  consensus/ core/         QPOS, QTD 확정성, 블록 처리
L4  qvm/                     QVM, QASM, JIT, 병렬 실행
L3  p2p/ economics/          인증 전송과 체인 경제
L2  qaudb/ encoding/ rlp/    저장소, 통신 포맷, 직렬화
L1  crypto/ types/ common/   Dilithium3, Kyber768, 핵심 타입
```

## 버전 정보

소스 릴리스 버전과 프로토콜 버전은 모두 `1.0.0`이며
`internal/version/version.go`에서 관리됩니다. 릴리스 빌드는 아래 `ldflags`로
버전, Git 커밋, UTC 빌드 시각을 주입할 수 있습니다:

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

## 빠른 시작

`go.mod`에 선언된 Go 버전이 필요합니다.

```sh
git clone https://github.com/Quantaureum/qau.git
cd qau

go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
go build -trimpath -o bin/qau-visor ./cmd/qau-visor
```

개발 노드 실행:

```sh
./bin/qaud --dev --network dev --datadir ./dev-data
```

공용 네트워크 실행:

```sh
./bin/qaud --network mainnet --datadir ./mainnet-data
./bin/qaud --network testnet --datadir ./testnet-data
```

메인넷과 테스트넷 제네시스 설정, 그리고 메인넷 canonical bootnode 기록은
클라이언트에 내장되어 있습니다.

## 하드웨어 및 실행 요구사항

노드에 엄격한 하드웨어 하한은 없습니다. Go 컴파일과 실행이 가능한 어느
머신이든 참여할 수 있습니다. 검증된 참고 구성은 다음과 같습니다:

| 역할 | CPU | 메모리 | 디스크 | 네트워크 |
| --- | --- | --- | --- | --- |
| 풀 노드 (메인넷/테스트넷) | 4 코어 | 8 GB | 200 GB SSD | 10 Mbps, 정적 공용 IP 권장 |
| 밸리데이터 | 8 코어 | 16 GB | 500 GB SSD | 100 Mbps, 낮은 지연 링크, 정적 IP 필수 |
| 개발넷 (로컬) | 2 코어 | 4 GB | 10 GB | 없음 |

참고:

- Dilithium3 서명 검증과 QTD 임계 서명은 CPU 집중적입니다. 밸리데이터 키와
  서명 상태는 밸리데이터 호스트에 유지해야 합니다.
- 상태는 체인 역사에 따라 증가합니다. SSD를 사용하고 데이터 디렉터리 잔여
  용량을 모니터링하세요.
- Go 도구 체인: `go.mod`에 선언된 버전을 사용하세요.
- 포트: P2P 수신 주소 기본값은 `0.0.0.0:9000` (`listenAddr`). HTTP
  JSON-RPC, WebSocket, 메트릭스 엔드포인트는 설정 가능 — 정확한 키는
  [설정 가이드](docs/CONFIGURATION.md) 참조.

## 네트워크 ID

| 네트워크 | Chain ID / Network ID | 16진수 Chain ID | 용도 |
| --- | ---: | --- | --- |
| 메인넷 | 1668 | `0x684` | 프로덕션 네트워크 |
| 테스트넷 | 1669 | `0x685` | 공용 테스트 네트워크 |
| 개발넷 | 1333 | `0x535` | 로컬 개발 |

## 저장소 구성

```text
cmd/            노드, CLI, 도구, 벤치마크 명령
crypto/         Dilithium3, Kyber768, QTD 암호
types/          블록, 트랜잭션, 주소, 핵심 타입
common/         공용 유틸리티
encoding/       통신 포맷, DAS, 소거 코드, FRI
rlp/ abi/       직렬화와 컨트랙트 ABI 인코딩
qaudb/          저장소, 상태, 블록 저장소, Verkle 트라이
consensus/      QPOS, 확정성, 선출, 슬래싱, 샤딩
core/           블록 생성과 검증
qvm/            QVM, QASM, JIT, 병렬 실행
node/           노드 오케스트레이션과 동기화
rpc/ graphql/   JSON-RPC, WebSocket, GraphQL API
p2p/            암호화 전송, 디스커버리, gossip
txpool/ miner/  트랜잭션 풀과 블록 봉인
wallet/ economics/ 지갑, 스테이킹, 보상, 거버넌스
rollup/ bridge/ 롤업과 크로스체인 브리지
privacy/ qzkp/  프라이버시와 영지식 증명
light/ lightclient/ 라이트 노드와 검증 컴포넌트
metrics/ log/ tracing/ 관측 가능성
contracts/      QASM과 Solidity 참조 컨트랙트
docs/           공개 문서
```

## JSON-RPC API

Ethereum 호환 `eth_chainId`, `eth_blockNumber`, `eth_getBalance`,
`eth_sendRawTransaction`, `eth_call`, `eth_estimateGas` 등을 지원합니다.
Quantaureum 전용 API는 `qau_` 네임스페이스를 사용합니다.

## SDK

노드는 Go 라이브러리로 직접 가져와 사용할 수 있습니다. Go, TypeScript,
Rust, C++, Java, Python SDK는 이 저장소의 `sdks/`에 포함되어 있습니다.

## 테스트

```sh
go test ./...
go test -race ./crypto/... ./consensus/... ./qvm/...
go test ./node -run "TestDefaultGenesis|TestTestnetGenesis|TestBuiltinNetworkGenesisValidation|TestGenesisValidate"
```

## 암호 사양

| 요소 | 알고리즘 | 표준 | 키 크기 | 서명 크기 |
| --- | --- | --- | --- | ---: |
| 서명 | Dilithium3 | NIST FIPS 204 | 공개 키 1952바이트 / 개인 키 4000바이트 | 3293바이트 |
| 키 교환 | Kyber768 | NIST FIPS 203 | 공개 키 1184바이트 / 개인 키 2400바이트 | 해당 없음 |
| 임계값 서명 | GM-QTD | Quantaureum 설계 | 그룹 공개 키 1952바이트 | 3293바이트 |
| 해시 | Blake2b-256 / SHA3-256 | RFC 7693 / FIPS 202 | 해당 없음 | 32바이트 |
| Keystore | AES-256-GCM / scrypt | NIST SP 800-38D / RFC 7914 | 해당 없음 | 해당 없음 |

HD 지갑 경로: `m/44'/1668'/0'/0/{index}`.

## 소스 릴리스 범위

이 저장소에는 노드와 도구 소스 코드, 내장 네트워크 설정, 컨트랙트 소스, 의존성
매니페스트, 테스트가 포함됩니다. 실행 설정, 개인 키, 인증서, 비밀번호, 배포
스크립트, 컨테이너 이미지, 빌드 결과물은 포함되지 않습니다.

## 문서

- [배포 가이드](docs/DEPLOYMENT.md)
- [네트워크 가이드](docs/NETWORK.md)
- [설정 가이드](docs/CONFIGURATION.md)
- [사용 가이드](docs/USAGE.md)

## 보안

개인 키, 니모닉, 비밀번호, 인증서, 프로덕션 네트워크 토폴로지를 저장소에 커밋하지
마세요. 실행 시 비밀 정보는 소스 트리 밖의 권한이 제한된 위치에서 관리하세요.

## 커뮤니티

- [Discord](https://discord.com/invite/MSctkBT5j)
- [X (@ldf1570073)](https://x.com/ldf1570073)
- [GitHub](https://github.com/Quantaureum/qau)

## 라이선스

Apache License 2.0. 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.
