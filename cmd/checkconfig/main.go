// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	LogLevel string `json:"logLevel"`
}

func main() {
	cfg := Config{}

	// load the default configuration
	defaultConfig := &Config{
		LogLevel: "info",
	}

	// if a config file exists, try loading it
	if _, err := os.Stat("config.json"); err == nil {
		data, err := os.ReadFile("config.json")
		if err != nil {
			fmt.Printf("Error reading config: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Printf("Error parsing config: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg = *defaultConfig
	}

	fmt.Printf("Current LogLevel: %s\n", cfg.LogLevel)
}
