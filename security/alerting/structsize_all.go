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
// Test ALL struct variants to find which ones achieve linter's target
// ============================================================================

// Alert variants
type Alert_orig struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	Details      map[string]any
	Acknowledged bool
	Timestamp    time.Time
	Resolved     bool
	ResolvedAt   time.Time
}

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

type Alert_v3 struct {
	Acknowledged bool
	Resolved     bool
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	ResolvedAt   time.Time
	Timestamp    time.Time
	Details      map[string]any
}

type Alert_v4 struct {
	Acknowledged bool
	Resolved     bool
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	Details      map[string]any
	ResolvedAt   time.Time
	Timestamp    time.Time
}

type Alert_v5 struct {
	ID           string
	Type         string
	Title        string
	Message      string
	Source       string
	Severity     int
	ResolvedAt   time.Time
	Acknowledged bool
	Resolved     bool
	Timestamp    time.Time
	Details      map[string]any
}

// AlertManager variants
type AM_v1 struct {
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

type AM_v2 struct {
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
	maxAlerts    int
	alertCount   int
	running      bool
	lastMinute   time.Time
}

type AM_v3 struct {
	maxAlerts    int
	alertCount   int
	lastMinute   time.Time
	running      bool
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
}

type AM_v4 struct {
	maxAlerts    int
	alertCount   int
	running      bool
	mu           sync.RWMutex
	lastMinute   time.Time
	recentAlerts map[string]time.Time
	channels     []any
	alerts       []*struct{}
	config       *struct{}
	stopCh       chan struct{}
}

// EmailConfig variants (alerting.go)
type EC_v1 struct {
	Enabled  bool
	UseTLS   bool
	Password []byte
	SMTPPort int
	SMTPHost string
	Username string
	From     string
	To       []string
}

type EC_v2 struct {
	Password []byte
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	From     string
	To       []string
}

type EC_v3 struct {
	Enabled  bool
	Password []byte
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	From     string
	To       []string
}

type EC_v4 struct {
	SMTPPort int
	Enabled  bool
	UseTLS   bool
	Password []byte
	SMTPHost string
	Username string
	From     string
	To       []string
}

type EC_v5 struct {
	Enabled  bool
	UseTLS   bool
	SMTPPort int
	SMTPHost string
	Username string
	Password []byte
	From     string
	To       []string
}

type EC_v6 struct {
	Password []byte
	Enabled  bool
	UseTLS   bool
	SMTPPort int
	SMTPHost string
	Username string
	From     string
	To       []string
}

type EC_v7 struct {
	Enabled  bool
	UseTLS   bool
	SMTPPort int
	Password []byte
	From     string
	To       []string
	SMTPHost string
	Username string
}

type EC_v8 struct {
	Enabled  bool
	UseTLS   bool
	SMTPPort int
	Password []byte
	To       []string
	From     string
	SMTPHost string
	Username string
}

type EC_v9 struct {
	Enabled  bool
	UseTLS   bool
	SMTPPort int
	Password []byte
	SMTPHost string
	From     string
	To       []string
	Username string
}

type EC_v10 struct {
	Enabled  bool
	UseTLS   bool
	SMTPPort int
	Password []byte
	Username string
	SMTPHost string
	From     string
	To       []string
}

// SlackConfig variants (all 3 strings - no meaningful ordering difference)
type SC_v1 struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type SC_v2 struct {
	WebhookURL string
	Channel    string
	Username   string
	Enabled    bool
}

// DiscordConfig variants
type DC_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

type DC_v2 struct {
	WebhookURL string
	Enabled    bool
	Username   string
}

type DC_v3 struct {
	Username   string
	Enabled    bool
	WebhookURL string
}

type DC_v4 struct {
	Enabled    bool
	WebhookURL string
	Username   string
}

// WebhookConfig variants
type WC_v1 struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string
}

type WC_v2 struct {
	Enabled bool
	URL     string
	Method  string
	Headers map[string]string
}

type WC_v3 struct {
	URL     string
	Method  string
	Headers map[string]string
	Enabled bool
}

type WC_v4 struct {
	URL     string
	Method  string
	Enabled bool
	Headers map[string]string
}

// PagerDutyConfig variants (Enabled + 3 strings - same issue as SlackConfig)
type PD_v1 struct {
	Enabled     bool
	RoutingKey  string
	ServiceName string
	Environment string
}

type PD_v2 struct {
	RoutingKey  string
	ServiceName string
	Environment string
	Enabled     bool
}

// ============================================================================
// config.go structs
// ============================================================================

type AC_v1 struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	DeduplicationWindow string
	RetryInterval       string
	Channels            any
}

type AC_v2 struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	RetryInterval       string
	DeduplicationWindow string
	Channels            any
}

type AC_v3 struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	DeduplicationWindow string
	RetryInterval       string
	Channels            any
}

type AC_v4 struct {
	MaxAlertsPerMinute  int
	MaxRetries          int
	Enabled             bool
	MinSeverity         string
	DeduplicationWindow string
	RetryInterval       string
	Channels            any
}

type CC_v1 struct {
	Console   any
	Email     any
	Slack     any
	Discord   any
	PagerDuty any
	Webhook   any
}

type CC_v2 struct {
	Webhook   any
	Console   any
	Email     any
	Slack     any
	Discord   any
	PagerDuty any
}

type CC_v3 struct {
	Console   struct{ Enabled bool }
	Email     struct{ Size int64 }
	Slack     struct{ Size int64 }
	Discord   struct{ Size int64 }
	PagerDuty struct{ Size int64 }
	Webhook   struct{ Size int64 }
}

type ECF_v1 struct {
	Enabled  bool
	SMTPPort int
	UseTLS   bool
	SMTPHost string
	Username string
	Password string
	From     string
	To       []string
}

type ECF_v2 struct {
	Enabled  bool
	SMTPHost string
	SMTPPort int
	Username string
	Password string
	From     string
	To       []string
	UseTLS   bool
}

type ECF_v3 struct {
	Enabled  bool
	SMTPPort int
	SMTPHost string
	Username string
	Password string
	From     string
	To       []string
	UseTLS   bool
}

type SCF_v1 struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type SCF_v2 struct {
	WebhookURL string
	Channel    string
	Username   string
	Enabled    bool
}

type DCF_v1 struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

type DCF_v2 struct {
	WebhookURL string
	Enabled    bool
	Username   string
}

type DCF_v3 struct {
	Username   string
	Enabled    bool
	WebhookURL string
}

type DCF_v4 struct {
	Enabled    bool
	WebhookURL string
	Username   string
}

type WCF_v1 struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string
}

type WCF_v2 struct {
	Enabled bool
	URL     string
	Method  string
	Headers map[string]string
}

type WCF_v3 struct {
	URL     string
	Method  string
	Headers map[string]string
	Enabled bool
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
	fmt.Println("=== Alert variants ===")
	measure("Alert (orig, maps+slices last)", reflect.TypeOf(Alert_orig{}))
	measure("Alert (v1: scalars+time first)", reflect.TypeOf(Alert_v1{}))
	measure("Alert (v2: time before bools)", reflect.TypeOf(Alert_v2{}))
	measure("Alert (v3: bools first)", reflect.TypeOf(Alert_v3{}))
	measure("Alert (v4: bools first, map mid)", reflect.TypeOf(Alert_v4{}))
	measure("Alert (v5: time first)", reflect.TypeOf(Alert_v5{}))

	fmt.Println("\n=== AlertManager variants ===")
	measure("AM (v1: scalars first)", reflect.TypeOf(AM_v1{}))
	measure("AM (v2: pointers first)", reflect.TypeOf(AM_v2{}))
	measure("AM (v3: mixed scalars)", reflect.TypeOf(AM_v3{}))
	measure("AM (v4: different order)", reflect.TypeOf(AM_v4{}))

	fmt.Println("\n=== EmailConfig variants (alerting.go) ===")
	measure("EC (v1: current - TLS+Pwd)", reflect.TypeOf(EC_v1{}))
	measure("EC (v2: Pwd first)", reflect.TypeOf(EC_v2{}))
	measure("EC (v3: Pwd mid)", reflect.TypeOf(EC_v3{}))
	measure("EC (v4: Port first)", reflect.TypeOf(EC_v4{}))
	measure("EC (v5: Pwd after strings)", reflect.TypeOf(EC_v5{}))
	measure("EC (v6: Pwd+TLS before Port)", reflect.TypeOf(EC_v6{}))
	measure("EC (v7: From before To)", reflect.TypeOf(EC_v7{}))
	measure("EC (v8: To before From)", reflect.TypeOf(EC_v8{}))
	measure("EC (v9: To before Username)", reflect.TypeOf(EC_v9{}))
	measure("EC (v10: Username before host)", reflect.TypeOf(EC_v10{}))

	fmt.Println("\n=== SlackConfig variants ===")
	measure("SC (v1: Enabled first)", reflect.TypeOf(SC_v1{}))
	measure("SC (v2: strings first)", reflect.TypeOf(SC_v2{}))

	fmt.Println("\n=== DiscordConfig variants ===")
	measure("DC (v1: Username before)", reflect.TypeOf(DC_v1{}))
	measure("DC (v2: WebhookURL first)", reflect.TypeOf(DC_v2{}))
	measure("DC (v3: Username first)", reflect.TypeOf(DC_v3{}))
	measure("DC (v4: WebhookURL+Username)", reflect.TypeOf(DC_v4{}))

	fmt.Println("\n=== WebhookConfig variants ===")
	measure("WC (v1: Headers first)", reflect.TypeOf(WC_v1{}))
	measure("WC (v2: Enabled first)", reflect.TypeOf(WC_v2{}))
	measure("WC (v3: URL+Method first)", reflect.TypeOf(WC_v3{}))
	measure("WC (v4: URL+Method+Enabled)", reflect.TypeOf(WC_v4{}))

	fmt.Println("\n=== PagerDutyConfig variants ===")
	measure("PD (v1: Enabled first)", reflect.TypeOf(PD_v1{}))
	measure("PD (v2: strings first)", reflect.TypeOf(PD_v2{}))

	fmt.Println("\n=== config.go structs ===")
	measure("AC (v1: current order)", reflect.TypeOf(AC_v1{}))
	measure("AC (v2: swapped Retry)", reflect.TypeOf(AC_v2{}))

	measure("CC (v1: current order)", reflect.TypeOf(CC_v1{}))
	measure("CC (v2: Webhook first)", reflect.TypeOf(CC_v2{}))

	measure("ECF (v1: scalars first)", reflect.TypeOf(ECF_v1{}))
	measure("ECF (v2: TLS last)", reflect.TypeOf(ECF_v2{}))
	measure("ECF (v3: UseTLS last)", reflect.TypeOf(ECF_v3{}))

	measure("SCF (v1: Enabled first)", reflect.TypeOf(SCF_v1{}))
	measure("SCF (v2: strings first)", reflect.TypeOf(SCF_v2{}))

	measure("DCF (v1: Username before)", reflect.TypeOf(DCF_v1{}))
	measure("DCF (v2: WebhookURL first)", reflect.TypeOf(DCF_v2{}))
	measure("DCF (v3: Username first)", reflect.TypeOf(DCF_v3{}))
	measure("DCF (v4: WebhookURL+Username)", reflect.TypeOf(DCF_v4{}))

	measure("WCF (v1: Headers first)", reflect.TypeOf(WCF_v1{}))
	measure("WCF (v2: Enabled first)", reflect.TypeOf(WCF_v2{}))
	measure("WCF (v3: URL+Method first)", reflect.TypeOf(WCF_v3{}))

	// Show layouts for problematic structs
	showLayout("Alert_orig", reflect.TypeOf(Alert_orig{}))
	showLayout("EC_v1", reflect.TypeOf(EC_v1{}))
	showLayout("EC_v2", reflect.TypeOf(EC_v2{}))
	showLayout("EC_v3", reflect.TypeOf(EC_v3{}))
	showLayout("SC_v1", reflect.TypeOf(SC_v1{}))
	showLayout("SC_v2", reflect.TypeOf(SC_v2{}))
	showLayout("DC_v1", reflect.TypeOf(DC_v1{}))
	showLayout("WC_v1", reflect.TypeOf(WC_v1{}))
	showLayout("ECF_v1", reflect.TypeOf(ECF_v1{}))
	showLayout("DCF_v1", reflect.TypeOf(DCF_v1{}))
}
