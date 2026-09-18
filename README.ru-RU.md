# Узел Quantaureum

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja-JP.md) | [한국어](README.ko-KR.md) | [Español](README.es.md) | Русский

Quantaureum — это квантово-устойчивая блокчейн-система Layer 1 с финальностью на
пороговых подписях и движком смарт-контрактов QVM.

## Обзор

Quantaureum — публичная post-quantum блокчейн-система Layer 1, написанная на Go
с нуля. Для подписей используется **Dilithium3** (NIST FIPS 204), для обмена
ключами — **Kyber768** (NIST FIPS 203), а блоки финализируются собственным
консенсусом **QPOS** и **пороговыми подписями QTD**.

Проект был начат автором **28 февраля 2025 года** и охватывает криптографию,
консенсус, виртуальную машину, сеть, хранилище и RPC.

## Основные возможности

| Возможность | Описание |
| --- | --- |
| Постквантовая криптография | Подписи Dilithium3 и обмен ключами Kyber768 |
| Пороговые подписи QTD | Распределенная генерация ключей и подписи финальности |
| Консенсус QPOS | BFT proof-of-stake, случайность, слэшинг и комитеты |
| QVM и QASM | Собственная виртуальная машина и контракты уровня ассемблера |
| Параллельное выполнение | Параллельное выполнение транзакций в стиле Block-STM |
| Доступность данных | Кодирование со стиранием, сэмплирование и FRI-обязательства |
| Шардирование | Многошардовая обработка и межшардовые сообщения |
| Rollup | Встроенный секвенсор и L1 bridge-контракты |
| Межцепочечной мост | Дизайн на основе Merkle-доказательств |
| Мультиподпись | Нативная поддержка Dilithium-мультиподписи |
| Легкий клиент | Легкая верификация на Verkle-доказательствах |
| SDK | Go-библиотека и отдельные SDK для основных языков |

## Архитектура

```text
L7  rpc/ graphql/            JSON-RPC 2.0, WebSocket и GraphQL
L6  node/ txpool/            Управление узлом и пул транзакций
L5  consensus/ core/         QPOS, QTD-финальность и обработка блоков
L4  qvm/                     QVM, QASM, JIT и параллельное выполнение
L3  p2p/ economics/          Аутентифицированный транспорт и экономика сети
L2  qaudb/ encoding/ rlp/    Хранение, форматы обмена и сериализация
L1  crypto/ types/ common/   Dilithium3, Kyber768 и базовые типы
```

## Метаданные версии

Версия исходного релиза и версия протокола равны `1.0.0` и определяются в
`internal/version/version.go`. Сборки релиза могут внедрять версию, Git-коммит и
UTC-время сборки:

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

## Быстрый старт

Требуется версия Go, указанная в `go.mod`.

```sh
git clone https://github.com/Quantaureum/qau.git
cd qau

go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
go build -trimpath -o bin/qau-visor ./cmd/qau-visor
```

Запуск узла разработки:

```sh
./bin/qaud --dev --network dev --datadir ./dev-data
```

Запуск публичной сети:

```sh
./bin/qaud --network mainnet --datadir ./mainnet-data
./bin/qaud --network testnet --datadir ./testnet-data
```

Конфигурации генезиса mainnet и testnet, а также canonical bootnode-записи
mainnet встроены в клиент.

## Требования к аппаратному обеспечению

У узла нет строгого минимума — таблица ниже содержит ПРЕДВАРИТЕЛЬНЫЕ
оценки, не основанные на измерениях:

| Роль | CPU | Память | Диск | Сеть |
| --- | --- | --- | --- | --- |
| Полный узел (mainnet/testnet) | 4 ядра | 8 ГБ | 200 ГБ SSD | 10 Мбит/с, рекомендуется статический публичный IP |
| Валидатор | 8 ядер | 16 ГБ | 500 ГБ SSD | 100 Мбит/с, канал с низкой задержкой, обязательный статический IP |
| Devnet (локальная) | 2 ядра | 4 ГБ | 10 ГБ | Нет |

Примечания:

- Проверка подписей Dilithium3 и пороговые подписи QTD интенсивно
  нагружают CPU; ключи и состояние подписи валидаторов должны
  оставаться на их host.
- Состояние растёт вместе с историей блока; используйте SSD и следите за
  свободным местом в каталоге данных.
- Go toolchain: версия, объявленная в `go.mod`.
- Порты: адрес прослушивания P2P по умолчанию `0.0.0.0:9000`
  (`listenAddr`); endpoints HTTP JSON-RPC, WebSocket и метрик настраиваются
  — см. [руководство по конфигурации](docs/CONFIGURATION.md).

## Идентификаторы сетей

| Сеть | Chain ID / Network ID | Chain ID в hex | Назначение |
| --- | ---: | --- | --- |
| Mainnet | 1668 | `0x684` | Продакшн-сеть |
| Testnet | 1669 | `0x685` | Публичная тестовая сеть |
| Devnet | 1333 | `0x535` | Локальная разработка |

## Структура репозитория

```text
cmd/            Команды узла, CLI, инструменты и бенчмарки
crypto/         Криптография Dilithium3, Kyber768 и QTD
types/          Блоки, транзакции, адреса и базовые типы
common/         Общие утилиты
encoding/       Форматы обмена, DAS, коды стирания и FRI
rlp/ abi/       Сериализация и кодирование ABI контрактов
qaudb/          Хранение, состояние, блоки и Verkle-trie
consensus/      QPOS, финальность, выборы, слэшинг и шардирование
core/           Сборка и валидация блоков
qvm/            QVM, QASM, JIT и параллельное выполнение
node/           Управление узлом и синхронизация
rpc/ graphql/   API JSON-RPC, WebSocket и GraphQL
p2p/            Зашифрованный транспорт, discovery и gossip
txpool/ miner/  Пул транзакций и запечатывание блоков
wallet/ economics/ Кошельки, стейкинг, награды и управление
rollup/ bridge/ Rollup-модули и межцепочечные мосты
privacy/ qzkp/  Приватность и доказательства с нулевым разглашением
light/ lightclient/ Легкий узел и компоненты проверки
metrics/ log/ tracing/ Наблюдаемость
contracts/      Контракты QASM и Solidity для справки
docs/           Публичная документация
```

## JSON-RPC API

Узел поддерживает Ethereum-совместимые методы: `eth_chainId`,
`eth_blockNumber`, `eth_getBalance`, `eth_sendRawTransaction`, `eth_call` и
`eth_estimateGas`. Методы Quantaureum используют пространство имен `qau_`.

## SDK

Узел можно напрямую импортировать как Go-библиотеку. SDK для Go, TypeScript,
Rust, C++, Java и Python включены в этот репозиторий в каталоге `sdks/`.

## Тестирование

```sh
go test ./...
go test -race ./crypto/... ./consensus/... ./qvm/...
go test ./node -run "TestDefaultGenesis|TestTestnetGenesis|TestBuiltinNetworkGenesisValidation|TestGenesisValidate"
```

## Криптографическая спецификация

| Примитив | Алгоритм | Стандарт | Размер ключа | Размер подписи |
| --- | --- | --- | --- | ---: |
| Подпись | Dilithium3 | NIST FIPS 204 | Публичный 1952 байт / приватный 4000 байт | 3293 байта |
| Обмен ключами | Kyber768 | NIST FIPS 203 | Публичный 1184 байта / приватный 2400 байт | Н/Д |
| Пороговая подпись | GM-QTD | Дизайн Quantaureum | Групповой публичный ключ 1952 байта | 3293 байта |
| Хеш | Blake2b-256 / SHA3-256 | RFC 7693 / FIPS 202 | Н/Д | 32 байта |
| Keystore | AES-256-GCM / scrypt | NIST SP 800-38D / RFC 7914 | Н/Д | Н/Д |

Путь HD-кошелька: `m/44'/1668'/0'/0/{index}`.

## Состав релиза

Репозиторий содержит исходный код узла и инструментов, встроенные публичные сети,
исходный код контрактов, манифесты Go-модулей и тесты. Он не содержит runtime
конфигурацию, приватные ключи, сертификаты, пароли, скрипты развертывания,
контейнерные образы и сгенерированные артефакты сборки.

## Документация

- [Руководство по развертыванию](docs/DEPLOYMENT.md)
- [Сетевое руководство](docs/NETWORK.md)
- [Руководство по конфигурации](docs/CONFIGURATION.md)
- [Руководство по использованию](docs/USAGE.md)

## Безопасность

Не отправляйте в репозиторий приватные ключи, мнемонические фразы, пароли,
сертификаты и топологию продакшн-сети. Секреты runtime храните вне дерева исходного
кода с ограниченными правами доступа.

## Сообщество

- [Discord](https://discord.com/invite/MSctkBT5j)
- [X (@ldf1570073)](https://x.com/ldf1570073)
- [GitHub](https://github.com/Quantaureum/qau)

## Лицензия

Apache License 2.0. См. [LICENSE](LICENSE).
