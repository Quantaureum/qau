// Quantaureum Node source, version 1.0.0.
package config

import (
	"testing"

	"github.com/quantaureum/qau/node"
)

// AUDIT run-3 qau.config/graphql-flag-ignored regression tests: the parsed
// --graphql value must reach node.Config, and a flag that was never passed must
// leave the legacy behavior untouched.

func TestApplyGraphqlFlagExplicitFalse(t *testing.T) {
	cfg := node.DefaultConfig()
	disabled := false

	applyGraphqlFlag(cfg, &CLI{GraphqlEnabled: &disabled, GraphqlSet: true})

	if !cfg.GraphqlExplicit {
		t.Fatal("explicit --graphql=false must be recorded as explicit")
	}
	if cfg.GraphqlEnabled {
		t.Fatal("explicit --graphql=false must clear GraphqlEnabled")
	}
}

func TestApplyGraphqlFlagExplicitTrue(t *testing.T) {
	cfg := node.DefaultConfig()
	enabled := true

	applyGraphqlFlag(cfg, &CLI{GraphqlEnabled: &enabled, GraphqlSet: true})

	if !cfg.GraphqlExplicit || !cfg.GraphqlEnabled {
		t.Fatalf("explicit --graphql=true must set both fields, got explicit=%v enabled=%v",
			cfg.GraphqlExplicit, cfg.GraphqlEnabled)
	}
}

func TestApplyGraphqlFlagOmittedKeepsLegacy(t *testing.T) {
	cfg := node.DefaultConfig()
	disabled := false

	applyGraphqlFlag(cfg, &CLI{GraphqlEnabled: &disabled, GraphqlSet: false})

	if cfg.GraphqlExplicit {
		t.Fatal("an omitted --graphql must not be treated as an explicit disable")
	}
}
