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
// alerting.go structs - EXACT copies from source
// ============================================================================

type Severity int

type NotificationChannel interface {
	Name() string
	Send(alert *Alert) error
	IsEnabled() bool
	Close() error
}

type Alert struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     Severity
	Details      map[string]any
	Acknowledged bool
	Timestamp    time.Time
	Resolved     bool
	ResolvedAt   time.Time
}

// Alert v1: scalars+strings first, bools before time.Time, map last
type Alert_v1 struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     Severity
	Acknowledged bool
	Resolved     bool
	ResolvedAt   time.Time
	Timestamp    time.Time
	Details      map[string]any
}

type AlertConfig struct{}

type AlertManagerOrig struct {
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []NotificationChannel
	alerts       []*Alert
	config       *AlertConfig
	stopCh       chan struct{}
	maxAlerts    int
	alertCount   int
	lastMinute   time.Time
	running      bool
}

// AlertManager v1: scalars first, then mu, then pointers/maps/slices
type AlertManager_v1 struct {
	maxAlerts    int
	alertCount   int
	running      bool
	lastMinute   time.Time
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []NotificationChannel
	alerts       []*Alert
	config       *AlertConfig
	stopCh       chan struct{}
}

type EmailConfigOrig struct {
	Enabled  bool
	SMTPHost string
	SMTPPort int
	Username string
	Password []byte
	From     string
	To       []string
	UseTLS   bool
}

// EmailConfig v1: scalars first (with Password before strings to align better)
type EmailConfig_v1 struct {
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	Password []byte
	SMTPHost string
	Username string
	From     string
	To       []string
}

// EmailConfig v2: Password first (8-byte aligned)
type EmailConfig_v2 struct {
	Password []byte
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	From     string
	To       []string
}

// EmailConfig v3: Enabled, UseTLS, Password together
type EmailConfig_v3 struct {
	Enabled  bool
	UseTLS   bool
	Password []byte
	SMTPPort int
	SMTPHost string
	Username string
	From     string
	To       []string
}

type SlackConfigOrig struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type SlackConfig_v1 struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type DiscordConfigOrig struct {
	Enabled    bool
	WebhookURL string
	Username   string
}

type DiscordConfig_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

type WebhookConfigOrig struct {
	Enabled bool
	URL     string
	Headers map[string]string
	Method  string
}

type WebhookConfig_v1 struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string
}

type WebhookConfig_v2 struct {
	Enabled bool
	Method  string
	URL     string
	Headers map[string]string
}

type PagerDutyConfigOrig struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

type PagerDutyConfig_v1 struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

// ============================================================================
// config.go structs - EXACT copies from source
// ============================================================================

type ConsoleConfigOrig struct {
	Enabled bool
}

type ChannelsConfigOrig struct {
	Console   ConsoleConfigOrig
	Email     EmailConfigFileOrig
	Slack     SlackConfigFileOrig
	Discord   DiscordConfigFileOrig
	PagerDuty PagerDutyConfigFileOrig
	Webhook   WebhookConfigFileOrig
}

type AlertingConfigOrig struct {
	Enabled             bool
	MinSeverity         string
	MaxAlertsPerMinute  int
	DeduplicationWindow string
	MaxRetries          int
	RetryInterval       string
	Channels            ChannelsConfigOrig
}

type AlertingConfig_v1 struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	DeduplicationWindow string
	RetryInterval       string
	Channels            ChannelsConfigOrig
}

type EmailConfigFileOrig struct {
	Enabled  bool
	SMTPHost string
	SMTPPort int
	Username string
	Password string
	From     string
	To       []string
	UseTLS   bool
}

type EmailConfigFile_v1 struct {
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	Password string
	From     string
	To       []string
}

type SlackConfigFileOrig struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type SlackConfigFile_v1 struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type DiscordConfigFileOrig struct {
	Enabled    bool
	WebhookURL string
	Username   string
}

type DiscordConfigFile_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

type PagerDutyConfigFileOrig struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

type PagerDutyConfigFile_v1 struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

type WebhookConfigFileOrig struct {
	Enabled bool
	URL     string
	Headers map[string]string
	Method  string
}

type WebhookConfigFile_v1 struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string
}

// ============================================================================
// Helper functions
// ============================================================================

func measure(name string, t reflect.Type) {
	fmt.Printf("%-35s Size=%3d  ptrBytes=%3d  align=%d\n", name, t.Size(), countPtrBytes(t), t.Align())
}

func countPtrBytes(t reflect.Type) int64 {
	var total int64
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		total += countFieldPtrBytes(f)
	}
	return total
}

func countFieldPtrBytes(f reflect.StructField) int64 {
	var total int64
	kind := f.Type.Kind()
	if kind == reflect.Ptr || kind == reflect.Slice || kind == reflect.Map ||
		kind == reflect.Chan || kind == reflect.Interface {
		total += int64(f.Type.Size())
	}
	if kind == reflect.Struct {
		for i := 0; i < f.Type.NumField(); i++ {
			total += countFieldPtrBytes(f.Type.Field(i))
		}
	}
	return total
}

func showLayout(name string, t reflect.Type) {
	fmt.Printf("\n%s (Size=%d, ptrBytes=%d):\n", name, t.Size(), countPtrBytes(t))
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fmt.Printf("  [%2d] %-20s offset=%3d  size=%3d  kind=%-12s\n",
			i, f.Name, f.Offset, f.Type.Size(), f.Type.Kind().String())
	}
}

func main() {
	fmt.Println("=== alerting.go structs ===")
	measure("Alert (orig)", reflect.TypeOf(Alert{}))
	measure("Alert (v1: scalars+time first)", reflect.TypeOf(Alert_v1{}))

	measure("AlertManager (orig)", reflect.TypeOf(AlertManagerOrig{}))
	measure("AlertManager (v1: scalars first)", reflect.TypeOf(AlertManager_v1{}))

	measure("EmailConfig (orig)", reflect.TypeOf(EmailConfigOrig{}))
	measure("EmailConfig (v1: scalars first)", reflect.TypeOf(EmailConfig_v1{}))
	measure("EmailConfig (v2: Password first)", reflect.TypeOf(EmailConfig_v2{}))
	measure("EmailConfig (v3: Enabled+UseTLS+Pwd)", reflect.TypeOf(EmailConfig_v3{}))

	measure("SlackConfig (orig)", reflect.TypeOf(SlackConfigOrig{}))
	measure("SlackConfig (v1)", reflect.TypeOf(SlackConfig_v1{}))

	measure("DiscordConfig (orig)", reflect.TypeOf(DiscordConfigOrig{}))
	measure("DiscordConfig (v1)", reflect.TypeOf(DiscordConfig_v1{}))

	measure("WebhookConfig (orig)", reflect.TypeOf(WebhookConfigOrig{}))
	measure("WebhookConfig (v1: Headers first)", reflect.TypeOf(WebhookConfig_v1{}))
	measure("WebhookConfig (v2: Enabled+Method)", reflect.TypeOf(WebhookConfig_v2{}))

	measure("PagerDutyConfig (orig)", reflect.TypeOf(PagerDutyConfigOrig{}))
	measure("PagerDutyConfig (v1)", reflect.TypeOf(PagerDutyConfig_v1{}))

	fmt.Println("\n=== config.go structs ===")
	measure("AlertingConfig (orig)", reflect.TypeOf(AlertingConfigOrig{}))
	measure("AlertingConfig (v1: ints first)", reflect.TypeOf(AlertingConfig_v1{}))

	measure("ChannelsConfig (orig)", reflect.TypeOf(ChannelsConfigOrig{}))

	measure("EmailConfigFile (orig)", reflect.TypeOf(EmailConfigFileOrig{}))
	measure("EmailConfigFile (v1: scalars first)", reflect.TypeOf(EmailConfigFile_v1{}))

	measure("SlackConfigFile (orig)", reflect.TypeOf(SlackConfigFileOrig{}))
	measure("SlackConfigFile (v1)", reflect.TypeOf(SlackConfigFile_v1{}))

	measure("DiscordConfigFile (orig)", reflect.TypeOf(DiscordConfigFileOrig{}))
	measure("DiscordConfigFile (v1)", reflect.TypeOf(DiscordConfigFile_v1{}))

	measure("PagerDutyConfigFile (orig)", reflect.TypeOf(PagerDutyConfigFileOrig{}))
	measure("PagerDutyConfigFile (v1)", reflect.TypeOf(PagerDutyConfigFile_v1{}))

	measure("WebhookConfigFile (orig)", reflect.TypeOf(WebhookConfigFileOrig{}))
	measure("WebhookConfigFile (v1: Headers first)", reflect.TypeOf(WebhookConfigFile_v1{}))

	// Detailed layouts for key structs
	showLayout("AlertOrig", reflect.TypeOf(Alert{}))
	showLayout("Alert_v1", reflect.TypeOf(Alert_v1{}))
	showLayout("AlertManagerOrig", reflect.TypeOf(AlertManagerOrig{}))
	showLayout("AlertManager_v1", reflect.TypeOf(AlertManager_v1{}))
	showLayout("EmailConfigOrig", reflect.TypeOf(EmailConfigOrig{}))
	showLayout("EmailConfig_v1", reflect.TypeOf(EmailConfig_v1{}))
	showLayout("EmailConfig_v2", reflect.TypeOf(EmailConfig_v2{}))
	showLayout("EmailConfigFileOrig", reflect.TypeOf(EmailConfigFileOrig{}))
	showLayout("EmailConfigFile_v1", reflect.TypeOf(EmailConfigFile_v1{}))
	showLayout("WebhookConfigOrig", reflect.TypeOf(WebhookConfigOrig{}))
	showLayout("WebhookConfig_v1", reflect.TypeOf(WebhookConfig_v1{}))
	showLayout("WebhookConfigFileOrig", reflect.TypeOf(WebhookConfigFileOrig{}))
	showLayout("WebhookConfigFile_v1", reflect.TypeOf(WebhookConfigFile_v1{}))
}
