# Nodo Quantaureum

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja-JP.md) | [한국어](README.ko-KR.md) | Español | [Русский](README.ru-RU.md)

Quantaureum es una blockchain Layer 1 con seguridad cuántica, finalidad mediante
firmas de umbral y un motor de contratos inteligentes QVM.

## Descripción

Quantaureum es una blockchain pública Layer 1 post-cuántica escrita en Go desde
cero. Usa **Dilithium3** (NIST FIPS 204) para firmas, **Kyber768** (NIST FIPS
203) para intercambio de claves, y un consenso **QPOS** propio con **firmas de
umbral QTD** para la finalidad de bloques.

El proyecto fue iniciado por su autor el **28 de febrero de 2025** y abarca
criptografía, consenso, máquina virtual, red, almacenamiento y RPC.

## Características principales

| Característica | Descripción |
| --- | --- |
| Criptografía post-cuántica | Firmas Dilithium3 e intercambio Kyber768 |
| Firmas de umbral QTD | Generación distribuida de claves y firmas de finalidad |
| Consenso QPOS | BFT de prueba de participación, aleatoriedad, slashing y comités |
| QVM y QASM | Máquina virtual propia y contratos a nivel de ensamblador |
| Ejecución paralela | Ejecución paralela de transacciones estilo Block-STM |
| Disponibilidad de datos | Codificación de borrado, muestreo y compromisos FRI |
| Sharding | Ejecución multi-shard y mensajería entre shards |
| Rollups | Secuenciador integrado y contratos puente en L1 |
| Puente entre cadenas | Diseño basado en pruebas Merkle |
| Billetera multifirma | Soporte nativo de multifirma Dilithium |
| Cliente ligero | Verificación ligera mediante pruebas Verkle |
| SDK | Biblioteca Go y SDK independientes en varios lenguajes |

## Arquitectura

```text
L7  rpc/ graphql/            JSON-RPC 2.0, WebSocket y GraphQL
L6  node/ txpool/            Orquestación del nodo y pool de transacciones
L5  consensus/ core/         QPOS, finalidad QTD y procesamiento de bloques
L4  qvm/                     QVM, QASM, JIT y ejecución paralela
L3  p2p/ economics/          Transporte autenticado y economía de la cadena
L2  qaudb/ encoding/ rlp/    Almacenamiento, formatos de red y serialización
L1  crypto/ types/ common/   Dilithium3, Kyber768 y tipos principales
```

## Metadatos de versión

La versión del código fuente y la versión del protocolo son `1.0.0`, definidas en
`internal/version/version.go`. Las compilaciones de publicación pueden inyectar
la versión, el commit de Git y la fecha de compilación UTC:

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

## Inicio rápido

Se requiere la versión de Go declarada en `go.mod`.

```sh
git clone https://github.com/Quantaureum/qau.git
cd qau

go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
go build -trimpath -o bin/qau-visor ./cmd/qau-visor
```

Nodo de desarrollo:

```sh
./bin/qaud --dev --network dev --datadir ./dev-data
```

Nodos de red pública:

```sh
./bin/qaud --network mainnet --datadir ./mainnet-data
./bin/qaud --network testnet --datadir ./testnet-data
```

La configuración génesis de mainnet y testnet, así como los registros canonical
bootnode de mainnet, están integrados en el cliente.

## Requisitos de hardware y ejecución

El nodo no tiene un mínimo estricto de hardware: cualquier máquina que
pueda compilar y ejecutar Go puede unirse. La tabla siguiente lista
**estimaciones provisionales (todavía no medidas)**:

| Rol | CPU | Memoria | Disco | Red |
| --- | --- | --- | --- | --- |
| Nodo completo (mainnet/testnet) | 4 núcleos | 8 GB | 200 GB SSD | 10 Mbps, IP pública estática recomendada |
| Validator | 8 núcleos | 16 GB | 500 GB SSD | 100 Mbps, enlace de baja latencia, IP estática obligatoria |
| Devnet (local) | 2 núcleos | 4 GB | 10 GB | Ninguno |

Notas:

- La verificación de firmas Dilithium3 y la firma por umbral QTD son
  intensivas en CPU; las claves y el estado de firma de los validators deben
  permanecer en su host.
- El estado crece con el historial de la cadena; se recomienda almacenamiento
  SSD y monitorizar el espacio libre del directorio de datos.
- Herramienta Go: la versión declarada en `go.mod`.
- Puertos: la dirección de escucha P2P es por defecto `0.0.0.0:9000`
  (`listenAddr`); los endpoints HTTP JSON-RPC, WebSocket y de métricas son
  configurables — ver la [guía de configuración](docs/CONFIGURATION.md).

## Identificadores de red

| Red | Chain ID / Network ID | Chain ID hexadecimal | Propósito |
| --- | ---: | --- | --- |
| Mainnet | 1668 | `0x684` | Red de producción |
| Testnet | 1669 | `0x685` | Red pública de pruebas |
| Devnet | 1333 | `0x535` | Desarrollo local |

## Estructura del repositorio

```text
cmd/            Comandos de nodo, CLI, herramientas y benchmarks
crypto/         Criptografía Dilithium3, Kyber768 y QTD
types/          Bloques, transacciones, direcciones y tipos principales
common/         Utilidades compartidas
encoding/       Formatos de red, DAS, códigos de borrado y FRI
rlp/ abi/       Serialización y codificación ABI de contratos
qaudb/          Almacenamiento, estado, bloques y Verkle trie
consensus/      QPOS, finalidad, elecciones, slashing y sharding
core/           Construcción y validación de bloques
qvm/            QVM, QASM, JIT y ejecución paralela
node/           Orquestación y sincronización del nodo
rpc/ graphql/   APIs JSON-RPC, WebSocket y GraphQL
p2p/            Transporte cifrado, descubrimiento y gossip
txpool/ miner/  Pool de transacciones y sellado de bloques
wallet/ economics/ Wallets, staking, recompensas y gobernanza
rollup/ bridge/ Rollups y componentes de puente entre cadenas
privacy/ qzkp/  Privacidad y pruebas de conocimiento cero
light/ lightclient/ Nodo ligero y componentes de verificación
metrics/ log/ tracing/ Observabilidad
contracts/      Contratos de referencia QASM y Solidity
docs/           Documentación pública
```

## API JSON-RPC

El nodo admite métodos compatibles con Ethereum, como `eth_chainId`,
`eth_blockNumber`, `eth_getBalance`, `eth_sendRawTransaction`, `eth_call` y
`eth_estimateGas`. Los métodos específicos de Quantaureum usan el espacio de
nombres `qau_`.

## SDK

El nodo puede importarse directamente como biblioteca de Go. Los SDK para Go,
TypeScript, Rust, C++, Java y Python están incluidos en este repositorio en
`sdks/`.

## Pruebas

```sh
go test ./...
go test -race ./crypto/... ./consensus/... ./qvm/...
go test ./node -run "TestDefaultGenesis|TestTestnetGenesis|TestBuiltinNetworkGenesisValidation|TestGenesisValidate"
```

## Especificación criptográfica

| Primitivo | Algoritmo | Estándar | Tamaño de clave | Tamaño de firma |
| --- | --- | --- | --- | ---: |
| Firma | Dilithium3 | NIST FIPS 204 | Pública 1952 bytes / privada 4000 bytes | 3293 bytes |
| Intercambio de claves | Kyber768 | NIST FIPS 203 | Pública 1184 bytes / privada 2400 bytes | N/A |
| Firma de umbral | GM-QTD | Diseño Quantaureum | Clave pública de grupo 1952 bytes | 3293 bytes |
| Hash | Blake2b-256 / SHA3-256 | RFC 7693 / FIPS 202 | N/A | 32 bytes |
| Keystore | AES-256-GCM / scrypt | NIST SP 800-38D / RFC 7914 | N/A | N/A |

ruta de billetera HD: `m/44'/1668'/0'/0/{index}`.

## Alcance del lanzamiento

El repositorio incluye el código fuente del nodo y las herramientas, las redes
públicas integradas, el código fuente de contratos, los manifiestos de módulos de
Go y las pruebas. No incluye configuración en ejecución, claves privadas,
certificados, contraseñas, scripts de despliegue, imágenes de contenedores ni
artefactos generados.

## Documentación

- [Guía de despliegue](docs/DEPLOYMENT.md)
- [Guía de red](docs/NETWORK.md)
- [Guía de configuración](docs/CONFIGURATION.md)
- [Guía de uso](docs/USAGE.md)

## Seguridad

No envíes al repositorio claves privadas, frases semilla, contraseñas,
certificados ni topología de producción. Gestiona los secretos en ejecución fuera
del árbol de código y con permisos restrictivos.

## Comunidad

- [Discord](https://discord.com/invite/MSctkBT5j)
- [X (@ldf1570073)](https://x.com/ldf1570073)
- [GitHub](https://github.com/Quantaureum/qau)

## Licencia

Apache License 2.0. Consulta [LICENSE](LICENSE).
