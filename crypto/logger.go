// Quantaureum Node source, version 1.0.0.
package crypto

import (
	logging "github.com/quantaureum/qau/log"
)

// cryptoLogger is the package-level structured logger for the crypto package.
//
// P3-LOG-01 FIX (R29, 2026-07-26): Previously, the crypto package called
// the package-level convenience functions logging.Warn() / logging.Error() /
// logging.Info() directly. These functions internally delegate to
// logging.Global(), which works functionally but produces log entries
// WITHOUT a "module" field — making it difficult for SIEM pipelines
// (ELK, Loki, Splunk) to filter crypto-module events from the rest of
// the node's logs.
//
// Fix: all crypto package log calls now go through cryptoLogger, which is
// derived from the global logger via WithModule("crypto"). This tags
// every log entry with module="crypto", enabling SIEM to:
//  1. Filter crypto events (key destruction failures, panic recovery,
//     scrypt weakness warnings) for security alerting.
//  2. Route crypto logs to a separate index/stream if desired.
//  3. Correlate crypto events across nodes by module.
//
// The logger is initialized lazily via init() to ensure the global logger
// is configured (via SetGlobal) before we derive the module logger. If
// SetGlobal is called AFTER init() (e.g., in main()), the cryptoLogger
// will still reference the OLD global logger — this is acceptable because
// the default global logger writes to stdout and is a valid sink. For
// production deployments that need a custom global logger, call
// SetGlobal BEFORE importing side effects (or re-init cryptoLogger
// via a sync.Once in the first call).
var cryptoLogger = logging.Global().WithModule("crypto")

// securityLogger is a crypto-module logger pre-tagged with
// category="SECURITY" for security-critical events.
//
// P3-LOG-02 FIX (R29, 2026-07-26): Audit R29 found that 27+ security
// event log calls in the crypto package (key destruction failures, key
// material leak warnings, panic recovery in batch verification) lacked
// a structured "category" field, forcing SIEM pipelines to rely on
// fragile message-text substring matching to identify security events.
//
// Fix: securityLogger is derived from cryptoLogger via WithField, so
// every log entry it emits carries BOTH module="crypto" AND
// category="SECURITY". This enables SIEM to:
//  1. Alert on ALL security events from the crypto module via a single
//     field query: category="SECURITY" AND module="crypto".
//  2. Route security events to a dedicated high-priority index/stream.
//  3. Build dashboards of key-management incidents across the fleet.
//
// Usage: use securityLogger for Warn/Error calls that relate to:
//   - Key destruction / zeroization failures
//   - Key material leak warnings (e.g., "key material may persist in heap")
//   - Panic recovery in cryptographic operations
//   - Weak parameter warnings (e.g., legacy scrypt, v1 keystore without AAD)
//   - Signature verification failures
//
// Use cryptoLogger (not securityLogger) for non-security Info/Warn calls.
var securityLogger = cryptoLogger.WithField("category", "SECURITY")
