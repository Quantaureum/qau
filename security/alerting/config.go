// Quantaureum Node source, version 1.0.0.
// Package alerting provides configuration loading for alert system.
package alerting

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// AlertingConfig represents the alerting configuration file structure
type AlertingConfig struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	DeduplicationWindow string
	RetryInterval       string
	Channels            ChannelsConfig
}

// ChannelsConfig holds all channel configurations
type ChannelsConfig struct {
	Console   ConsoleConfig       `json:"console"`
	Email     EmailConfigFile     `json:"email"`
	Slack     SlackConfigFile     `json:"slack"`
	Discord   DiscordConfigFile   `json:"discord"`
	PagerDuty PagerDutyConfigFile `json:"pagerduty"`
	Webhook   WebhookConfigFile   `json:"webhook"`
}

// ConsoleConfig for console channel
type ConsoleConfig struct {
	Enabled bool `json:"enabled"`
}

// EmailConfigFile for email channel (with env var support)
type EmailConfigFile struct {
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string   `json:"smtp_host"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// SlackConfigFile for Slack channel
type SlackConfigFile struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
}

// DiscordConfigFile for Discord channel
type DiscordConfigFile struct {
	Enabled    bool
	Username   string
	WebhookURL string `json:"webhook_url"`
}

// PagerDutyConfigFile for PagerDuty channel
type PagerDutyConfigFile struct {
	Enabled     bool   `json:"enabled"`
	RoutingKey  string `json:"routing_key"`
	ServiceName string `json:"service_name"`
	Environment string `json:"environment"`
}

// WebhookConfigFile for generic webhook channel
type WebhookConfigFile struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string `json:"method"`
}

// LoadConfig loads alerting configuration from a file
func LoadConfig(path string) (*AlertingConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}

	var config AlertingConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// expandEnvVars replaces ${VAR} with environment variable values
func expandEnvVars(s string) string {
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		varName := s[2 : len(s)-1]
		return os.Getenv(varName)
	}
	return s
}

// CreateAlertManager creates an AlertManager from configuration
func CreateAlertManager(configPath string) (*AlertManager, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		// Return default manager if config not found
		return NewAlertManager(DefaultAlertConfig()), nil
	}

	// Parse alert config
	alertConfig := &AlertConfig{
		MinSeverity:        parseSeverity(config.MinSeverity),
		MaxAlertsPerMinute: config.MaxAlertsPerMinute,
		MaxRetries:         config.MaxRetries,
	}

	if config.DeduplicationWindow != "" {
		if d, err := time.ParseDuration(config.DeduplicationWindow); err == nil {
			alertConfig.DeduplicationWindow = d
		}
	}

	if config.RetryInterval != "" {
		if d, err := time.ParseDuration(config.RetryInterval); err == nil {
			alertConfig.RetryInterval = d
		}
	}

	manager := NewAlertManager(alertConfig)

	// Add channels
	if config.Channels.Console.Enabled {
		manager.AddChannel(NewConsoleChannel(true))
	}

	if config.Channels.Email.Enabled {
		manager.AddChannel(NewEmailChannel(&EmailConfig{
			Enabled:  true,
			SMTPHost: config.Channels.Email.SMTPHost,
			SMTPPort: config.Channels.Email.SMTPPort,
			Username: config.Channels.Email.Username,
			Password: []byte(expandEnvVars(config.Channels.Email.Password)),
			From:     config.Channels.Email.From,
			To:       config.Channels.Email.To,
			UseTLS:   config.Channels.Email.UseTLS,
		}))
	}

	if config.Channels.Slack.Enabled {
		manager.AddChannel(NewSlackChannel(&SlackConfig{
			Enabled:    true,
			WebhookURL: expandEnvVars(config.Channels.Slack.WebhookURL),
			Channel:    config.Channels.Slack.Channel,
			Username:   config.Channels.Slack.Username,
		}))
	}

	if config.Channels.Discord.Enabled {
		manager.AddChannel(NewDiscordChannel(&DiscordConfig{
			Enabled:    true,
			WebhookURL: expandEnvVars(config.Channels.Discord.WebhookURL),
			Username:   config.Channels.Discord.Username,
		}))
	}

	if config.Channels.PagerDuty.Enabled {
		manager.AddChannel(NewPagerDutyChannel(&PagerDutyConfig{
			Enabled:     true,
			RoutingKey:  expandEnvVars(config.Channels.PagerDuty.RoutingKey),
			ServiceName: config.Channels.PagerDuty.ServiceName,
			Environment: config.Channels.PagerDuty.Environment,
		}))
	}

	if config.Channels.Webhook.Enabled {
		headers := make(map[string]string)
		for k, v := range config.Channels.Webhook.Headers {
			headers[k] = expandEnvVars(v)
		}
		manager.AddChannel(NewWebhookChannel(&WebhookConfig{
			Enabled: true,
			URL:     expandEnvVars(config.Channels.Webhook.URL),
			Headers: headers,
			Method:  config.Channels.Webhook.Method,
		}))
	}

	return manager, nil
}

// parseSeverity converts string to Severity
func parseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "info":
		return SeverityInfo
	case "warning":
		return SeverityWarning
	case "error":
		return SeverityError
	case "critical":
		return SeverityCritical
	default:
		return SeverityWarning
	}
}
