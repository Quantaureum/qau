// Quantaureum Node source, version 1.0.0.
//go:build ignore

package main

import (
	"fmt"
	"reflect"
	"sync"
	"time"
)

// ============================================================================
// Current alerting.go structs (as edited)
// ============================================================================

type Severity int

type Alert struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Title        string         `json:"title"`
	Message      string         `json:"message"`
	Source       string         `json:"source"`
	Severity     Severity       `json:"severity"`
	Acknowledged bool           `json:"acknowledged"`
	Resolved     bool           `json:"resolved"`
	ResolvedAt   time.Time      `json:"resolved_at"`
	Timestamp    time.Time      `json:"timestamp"`
	Details      map[string]any `json:"details"`
}

type AlertManager struct {
	maxAlerts  int
	alertCount int
	running    bool
	lastMinute time.Time

	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
}

// SlackConfig v1: Enabled first, then strings
type SlackConfig_v1 struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

// SlackConfig v2: all strings together
type SlackConfig_v2 struct {
	WebhookURL string
	Channel    string
	Username   string
	Enabled    bool
}

// DiscordConfig v1: Username before WebhookURL
type DiscordConfig_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

// DiscordConfig v2: WebhookURL first
type DiscordConfig_v2 struct {
	WebhookURL string
	Enabled    bool
	Username   string
}

// PagerDutyConfig: all strings
type PagerDutyConfig struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

// EmailConfig v1: Enabled+UseTLS+Password+SMTPPort first
type EmailConfig_v1 struct {
	Enabled  bool
	UseTLS   bool
	Password []byte
	SMTPPort int
	SMTPHost string
	Username string
	From     string
	To       []string
}

// EmailConfig v2: To before From
type EmailConfig_v2 struct {
	Enabled  bool
	UseTLS   bool
	Password []byte
	SMTPPort int
	SMTPHost string
	Username string
	To       []string
	From     string
}

// EmailConfig v3: UseTLS after Password
type EmailConfig_v3 struct {
	Enabled  bool
	Password []byte
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	From     string
	To       []string
}

// WebhookConfig v1: Headers first
type WebhookConfig_v1 struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string
}

// WebhookConfig v2: Enabled+Method, then Headers
type WebhookConfig_v2 struct {
	Enabled bool
	Method  string
	URL     string
	Headers map[string]string
}

// ============================================================================
// Current config.go structs (as edited)
// ============================================================================

type AlertingConfig struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	DeduplicationWindow string
	RetryInterval       string
	Channels            ChannelsConfig
}

type ChannelsConfig struct {
	Console   ConsoleConfig
	Email     EmailConfigFile
	Slack     SlackConfigFile
	Discord   DiscordConfigFile_v1
	PagerDuty PagerDutyConfigFile
	Webhook   WebhookConfigFile
}

type ConsoleConfig struct {
	Enabled bool
}

type EmailConfigFile struct {
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	Password string
	From     string
	To       []string
}

type SlackConfigFile struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type DiscordConfigFile_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

type DiscordConfigFile_v2 struct {
	Enabled    bool
	WebhookURL string
	Username   string
}

type PagerDutyConfigFile struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

type WebhookConfigFile struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string
}

// ============================================================================
// Helper
// ============================================================================

func measure(name string, t reflect.Type) {
	fmt.Printf("%-35s Size=%3d  align=%d\n", name, t.Size(), t.Align())
}

func showLayout(name string, t reflect.Type) {
	fmt.Printf("\n%s (Size=%d):\n", name, t.Size())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fmt.Printf("  [%2d] %-20s offset=%3d  size=%3d  kind=%-12s\n",
			i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind().String())
	}
}

func main() {
	fmt.Println("=== alerting.go structs (current) ===")
	measure("Alert (current)", reflect.TypeOf(Alert{}))
	measure("AlertManager (current)", reflect.TypeOf(AlertManager{}))

	// Try different orderings for SlackConfig
	measure("SlackConfig (v1: Enabled first)", reflect.TypeOf(SlackConfig_v1{}))
	measure("SlackConfig (v2: strings first)", reflect.TypeOf(SlackConfig_v2{}))

	// Try different orderings for DiscordConfig
	measure("DiscordConfig (v1: Username before)", reflect.TypeOf(DiscordConfig_v1{}))
	measure("DiscordConfig (v2: WebhookURL first)", reflect.TypeOf(DiscordConfig_v2{}))

	measure("PagerDutyConfig (current)", reflect.TypeOf(PagerDutyConfig{}))

	// Try different orderings for EmailConfig
	measure("EmailConfig (v1: current)", reflect.TypeOf(EmailConfig_v1{}))
	measure("EmailConfig (v2: To before From)", reflect.TypeOf(EmailConfig_v2{}))
	measure("EmailConfig (v3: UseTLS after Pwd)", reflect.TypeOf(EmailConfig_v3{}))

	// Try different orderings for WebhookConfig
	measure("WebhookConfig (v1: Headers first)", reflect.TypeOf(WebhookConfig_v1{}))
	measure("WebhookConfig (v2: Enabled+Method)", reflect.TypeOf(WebhookConfig_v2{}))

	fmt.Println("\n=== config.go structs (current) ===")
	measure("AlertingConfig (current)", reflect.TypeOf(AlertingConfig{}))
	measure("ChannelsConfig (current)", reflect.TypeOf(ChannelsConfig{}))
	measure("EmailConfigFile (current)", reflect.TypeOf(EmailConfigFile{}))
	measure("SlackConfigFile (current)", reflect.TypeOf(SlackConfigFile{}))
	measure("DiscordConfigFile (v1: Username before)", reflect.TypeOf(DiscordConfigFile_v1{}))
	measure("DiscordConfigFile (v2: WebhookURL first)", reflect.TypeOf(DiscordConfigFile_v2{}))
	measure("PagerDutyConfigFile (current)", reflect.TypeOf(PagerDutyConfigFile{}))
	measure("WebhookConfigFile (current)", reflect.TypeOf(WebhookConfigFile{}))

	fmt.Println()
	showLayout("Alert", reflect.TypeOf(Alert{}))
	showLayout("AlertManager", reflect.TypeOf(AlertManager{}))
	showLayout("SlackConfig_v1", reflect.TypeOf(SlackConfig_v1{}))
	showLayout("SlackConfig_v2", reflect.TypeOf(SlackConfig_v2{}))
	showLayout("DiscordConfig_v1", reflect.TypeOf(DiscordConfig_v1{}))
	showLayout("DiscordConfig_v2", reflect.TypeOf(DiscordConfig_v2{}))
	showLayout("PagerDutyConfig", reflect.TypeOf(PagerDutyConfig{}))
	showLayout("EmailConfig_v1", reflect.TypeOf(EmailConfig_v1{}))
	showLayout("EmailConfig_v2", reflect.TypeOf(EmailConfig_v2{}))
	showLayout("EmailConfig_v3", reflect.TypeOf(EmailConfig_v3{}))
	showLayout("WebhookConfig_v1", reflect.TypeOf(WebhookConfig_v1{}))
	showLayout("WebhookConfig_v2", reflect.TypeOf(WebhookConfig_v2{}))
	showLayout("AlertingConfig", reflect.TypeOf(AlertingConfig{}))
	showLayout("ChannelsConfig", reflect.TypeOf(ChannelsConfig{}))
	showLayout("EmailConfigFile", reflect.TypeOf(EmailConfigFile{}))
	showLayout("DiscordConfigFile_v1", reflect.TypeOf(DiscordConfigFile_v1{}))
	showLayout("DiscordConfigFile_v2", reflect.TypeOf(DiscordConfigFile_v2{}))
	showLayout("WebhookConfigFile", reflect.TypeOf(WebhookConfigFile{}))
}
