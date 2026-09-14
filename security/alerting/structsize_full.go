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
// alerting.go structs
// ============================================================================

// Original Alert (from alerting.go line 44)
type AlertOrig struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Title        string         `json:"title"`
	Message      string         `json:"message"`
	Source       string         `json:"source"`
	Severity     int            `json:"severity"`
	Details      map[string]any `json:"details"`
	Acknowledged bool           `json:"acknowledged"`
	Timestamp    time.Time      `json:"timestamp"`
	Resolved     bool           `json:"resolved"`
	ResolvedAt   time.Time      `json:"resolved_at"`
}

// Alert v1: scalars first (strings, int, bools), then maps/slices/pointers
type Alert_v1 struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	Acknowledged bool
	Resolved     bool
	ResolvedAt   time.Time
	Timestamp    time.Time
	Details      map[string]any
}

// Alert v2: strings, int, time.Time, bools
type Alert_v2 struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	ResolvedAt   time.Time
	Timestamp    time.Time
	Acknowledged bool
	Resolved     bool
	Details      map[string]any
}

// Alert v3: strings, int, bools, time.Time
type Alert_v3 struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	Acknowledged bool
	Resolved     bool
	Details      map[string]any
	ResolvedAt   time.Time
	Timestamp    time.Time
}

// Alert v4: strings, int, time.Time, bools, map
type Alert_v4 struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	ResolvedAt   time.Time
	Timestamp    time.Time
	Acknowledged bool
	Resolved     bool
	Details      map[string]any
}

// Original EmailConfig
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

// EmailConfig v1: scalars first, then pointers/slices
type EmailConfig_v1 struct {
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	Password []byte
	From     string
	To       []string
}

// Original SlackConfig
type SlackConfigOrig struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

// SlackConfig v1: scalars first, then pointers/slices
type SlackConfig_v1 struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

// Original DiscordConfig
type DiscordConfigOrig struct {
	Enabled    bool
	WebhookURL string
	Username   string
}

// DiscordConfig v1: scalars first, then pointers/slices
type DiscordConfig_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

// Original WebhookConfig
type WebhookConfigOrig struct {
	Enabled bool
	URL     string
	Headers map[string]string
	Method  string
}

// WebhookConfig v1: scalars first, then pointers/slices
type WebhookConfig_v1 struct {
	Enabled bool
	URL     string
	Method  string
	Headers map[string]string
}

// Original PagerDutyConfig
type PagerDutyConfigOrig struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

// PagerDutyConfig v1: scalars first, then pointers/slices
type PagerDutyConfig_v1 struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

// Original AlertManager
type AlertManagerOrig struct {
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
	maxAlerts    int
	alertCount   int
	lastMinute   time.Time
	running      bool
}

// AlertManager v1: scalars first, then pointers, then map/slice/chan
type AlertManager_v1 struct {
	maxAlerts    int
	alertCount   int
	running      bool
	lastMinute   time.Time
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
}

// AlertManager v2: scalars (with time) first, then mu, then pointers
type AlertManager_v2 struct {
	maxAlerts    int
	alertCount   int
	running      bool
	lastMinute   time.Time
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
}

// ============================================================================
// config.go structs
// ============================================================================

type NotificationChannelFile any
type AlertConfigFile struct{}

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

type ChannelsConfigOrig struct {
	Console   ConsoleConfigOrig
	Email     EmailConfigFileOrig
	Slack     SlackConfigFileOrig
	Discord   DiscordConfigFileOrig
	PagerDuty PagerDutyConfigFileOrig
	Webhook   WebhookConfigFileOrig
}

type ChannelsConfig_v1 struct {
	Console   ConsoleConfigOrig
	Email     EmailConfigFileOrig
	Slack     SlackConfigFileOrig
	Discord   DiscordConfigFileOrig
	PagerDuty PagerDutyConfigFileOrig
	Webhook   WebhookConfigFileOrig
}

type ConsoleConfigOrig struct {
	Enabled bool
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
	Enabled bool
	URL     string
	Method  string
	Headers map[string]string
}

// ============================================================================
// Helper
// ============================================================================

func measure(name string, t reflect.Type) {
	fmt.Printf("%-30s Size=%3d  ptrBytes=%3d  align=%d\n", name, t.Size(), countPtrBytes(t), t.Align())
}

func countPtrBytes(t reflect.Type) int64 {
	var total int64
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		kind := f.Type.Kind()
		if kind == reflect.Ptr || kind == reflect.Slice || kind == reflect.Map ||
			kind == reflect.Chan || kind == reflect.Interface {
			total += int64(f.Type.Size())
		}
	}
	return total
}

func showLayout(name string, t reflect.Type) {
	fmt.Printf("\n%s (Size=%d):\n", name, t.Size())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		kind := f.Type.Kind()
		isPtr := kind == reflect.Ptr || kind == reflect.Slice || kind == reflect.Map ||
			kind == reflect.Chan || kind == reflect.Interface
		fmt.Printf("  [%2d] %-20s offset=%3d  size=%3d  kind=%-12s  ptr=%v\n",
			i, f.Name, f.Offset, f.Type.Size(), kind.String(), isPtr)
	}
}

func main() {
	fmt.Println("=== alerting.go structs ===")
	measure("Alert (orig)", reflect.TypeOf(AlertOrig{}))
	measure("Alert (v1: scalars+time first)", reflect.TypeOf(Alert_v1{}))
	measure("Alert (v2: time before bools)", reflect.TypeOf(Alert_v2{}))
	measure("Alert (v3: bools after map)", reflect.TypeOf(Alert_v3{}))
	measure("Alert (v4: time before map)", reflect.TypeOf(Alert_v4{}))

	measure("EmailConfig (orig)", reflect.TypeOf(EmailConfigOrig{}))
	measure("EmailConfig (v1: scalars first)", reflect.TypeOf(EmailConfig_v1{}))

	measure("SlackConfig (orig)", reflect.TypeOf(SlackConfigOrig{}))
	measure("SlackConfig (v1)", reflect.TypeOf(SlackConfig_v1{}))

	measure("DiscordConfig (orig)", reflect.TypeOf(DiscordConfigOrig{}))
	measure("DiscordConfig (v1)", reflect.TypeOf(DiscordConfig_v1{}))

	measure("WebhookConfig (orig)", reflect.TypeOf(WebhookConfigOrig{}))
	measure("WebhookConfig (v1)", reflect.TypeOf(WebhookConfig_v1{}))

	measure("PagerDutyConfig (orig)", reflect.TypeOf(PagerDutyConfigOrig{}))
	measure("PagerDutyConfig (v1)", reflect.TypeOf(PagerDutyConfig_v1{}))

	measure("AlertManager (orig)", reflect.TypeOf(AlertManagerOrig{}))
	measure("AlertManager (v1: scalars first)", reflect.TypeOf(AlertManager_v1{}))

	fmt.Println("\n=== config.go structs ===")
	measure("AlertingConfig (orig)", reflect.TypeOf(AlertingConfigOrig{}))
	measure("AlertingConfig (v1)", reflect.TypeOf(AlertingConfig_v1{}))

	measure("ChannelsConfig (orig)", reflect.TypeOf(ChannelsConfigOrig{}))
	measure("ChannelsConfig (v1)", reflect.TypeOf(ChannelsConfig_v1{}))

	measure("EmailConfigFile (orig)", reflect.TypeOf(EmailConfigFileOrig{}))
	measure("EmailConfigFile (v1)", reflect.TypeOf(EmailConfigFile_v1{}))

	measure("SlackConfigFile (orig)", reflect.TypeOf(SlackConfigFileOrig{}))
	measure("SlackConfigFile (v1)", reflect.TypeOf(SlackConfigFile_v1{}))

	measure("DiscordConfigFile (orig)", reflect.TypeOf(DiscordConfigFileOrig{}))
	measure("DiscordConfigFile (v1)", reflect.TypeOf(DiscordConfigFile_v1{}))

	measure("PagerDutyConfigFile (orig)", reflect.TypeOf(PagerDutyConfigFileOrig{}))
	measure("PagerDutyConfigFile (v1)", reflect.TypeOf(PagerDutyConfigFile_v1{}))

	measure("WebhookConfigFile (orig)", reflect.TypeOf(WebhookConfigFileOrig{}))
	measure("WebhookConfigFile (v1)", reflect.TypeOf(WebhookConfigFile_v1{}))

	// Show detailed layout for key structs
	showLayout("AlertOrig", reflect.TypeOf(AlertOrig{}))
	showLayout("Alert_v1", reflect.TypeOf(Alert_v1{}))
	showLayout("AlertManagerOrig", reflect.TypeOf(AlertManagerOrig{}))
	showLayout("AlertManager_v1", reflect.TypeOf(AlertManager_v1{}))
	showLayout("AlertingConfigOrig", reflect.TypeOf(AlertingConfigOrig{}))
	showLayout("AlertingConfig_v1", reflect.TypeOf(AlertingConfig_v1{}))
}
