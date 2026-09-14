// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantaureum/qau/node"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage node configuration",
		Long:  "View, edit, and validate node configuration files.",
	}

	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigInitCmd())
	cmd.AddCommand(newConfigSetCmd())
	cmd.AddCommand(newConfigGetCmd())
	cmd.AddCommand(newConfigValidateCmd())

	return cmd
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Long:  "Display the current node configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showConfig()
		},
	}
}

func newConfigInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize default configuration",
		Long:  "Create a new configuration file with default values.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing configuration")
	return cmd
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long:  "Set a specific configuration value. Use dot notation for nested keys.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setConfigValue(args[0], args[1])
		},
	}
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Long:  "Get a specific configuration value. Use dot notation for nested keys.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return getConfigValue(args[0])
		},
	}
}

func newConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration",
		Long:  "Validate the current configuration file.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return validateConfig()
		},
	}
}

func getConfigPath() string {
	if configFile != "" {
		return configFile
	}
	return filepath.Join(dataDir, "config.json")
}

func showConfig() error {
	configPath := getConfigPath()

	cfg, err := node.LoadConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No configuration file found. Using defaults.")
			cfg = node.DefaultConfig()
		} else {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format config: %w", err)
	}

	fmt.Printf("Configuration (%s):\n", configPath)
	fmt.Println(string(data))
	return nil
}

func initConfig(force bool) error {
	configPath := getConfigPath()

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil && !force {
		return fmt.Errorf("configuration file already exists at %s. Use --force to overwrite", configPath)
	}

	// Create default config
	cfg := node.DefaultConfig()
	cfg.DataDir = dataDir

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save config
	if err := cfg.SaveConfig(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Configuration initialized at %s\n", configPath)
	return nil
}

func setConfigValue(key, value string) error {
	configPath := getConfigPath()

	// Load existing config or create default
	cfg, err := node.LoadConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = node.DefaultConfig()
		} else {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Convert config to map for easier manipulation
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	var configMap map[string]any
	if err := json.Unmarshal(data, &configMap); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set the value using dot notation
	if err := setNestedValue(configMap, key, value); err != nil {
		return err
	}

	// Convert back to config struct
	data, err = json.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal updated config: %w", err)
	}

	// Save config
	if err := cfg.SaveConfig(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Set %s = %s\n", key, value)
	return nil
}

func getConfigValue(key string) error {
	configPath := getConfigPath()

	cfg, err := node.LoadConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = node.DefaultConfig()
		} else {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Convert config to map
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	var configMap map[string]any
	if err := json.Unmarshal(data, &configMap); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Get the value using dot notation
	value, err := getNestedValue(configMap, key)
	if err != nil {
		return err
	}

	fmt.Printf("%s = %v\n", key, value)
	return nil
}

func validateConfig() error {
	configPath := getConfigPath()

	cfg, err := node.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	fmt.Println("Configuration is valid.")
	return nil
}

// setNestedValue sets a value in a nested map using dot notation
func setNestedValue(m map[string]any, key, value string) error {
	parts := strings.Split(key, ".")
	current := m

	for i, part := range parts[:len(parts)-1] {
		if next, ok := current[part]; ok {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return fmt.Errorf("key %s is not a map", strings.Join(parts[:i+1], "."))
			}
		} else {
			// Create nested map
			newMap := make(map[string]any)
			current[part] = newMap
			current = newMap
		}
	}

	// Parse value type
	finalKey := parts[len(parts)-1]
	current[finalKey] = parseValue(value)
	return nil
}

// getNestedValue gets a value from a nested map using dot notation
func getNestedValue(m map[string]any, key string) (any, error) {
	parts := strings.Split(key, ".")
	current := m

	for i, part := range parts[:len(parts)-1] {
		if next, ok := current[part]; ok {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return nil, fmt.Errorf("key %s is not a map", strings.Join(parts[:i+1], "."))
			}
		} else {
			return nil, fmt.Errorf("key %s not found", strings.Join(parts[:i+1], "."))
		}
	}

	finalKey := parts[len(parts)-1]
	if value, ok := current[finalKey]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("key %s not found", key)
}

// parseValue attempts to parse a string value into its appropriate type
func parseValue(s string) any {
	// Try boolean
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}

	// Try integer
	var intVal int64
	if _, err := fmt.Sscanf(s, "%d", &intVal); err == nil {
		return intVal
	}

	// Try float
	var floatVal float64
	if _, err := fmt.Sscanf(s, "%f", &floatVal); err == nil {
		return floatVal
	}

	// Return as string
	return s
}
