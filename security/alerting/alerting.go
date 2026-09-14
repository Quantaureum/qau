// Quantaureum Node source, version 1.0.0.
// Package alerting provides security alert notification system.
package alerting

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"sync"
	"text/template"
	"time"
)

// Alert severity levels
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Alert represents a security alert
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

// NotificationChannel defines the interface for notification channels
type NotificationChannel interface {
	Name() string
	Send(alert *Alert) error
	IsEnabled() bool
	// Close releases resources held by the channel. For EmailChannel this
	// securely zeroizes sensitive configuration such as SMTP passwords.
	Close() error
}

// AlertConfig holds alerting configuration
type AlertConfig struct {
	// Minimum severity to send alerts
	MinSeverity Severity

	// Rate limiting
	MaxAlertsPerMinute int

	// Deduplication window
	DeduplicationWindow time.Duration

	// Retry settings
	MaxRetries    int
	RetryInterval time.Duration
}

// DefaultAlertConfig returns default configuration
func DefaultAlertConfig() *AlertConfig {
	return &AlertConfig{
		MinSeverity:         SeverityWarning,
		MaxAlertsPerMinute:  60,
		DeduplicationWindow: 5 * time.Minute,
		MaxRetries:          3,
		RetryInterval:       time.Second,
	}
}

// AlertManager manages security alerts
type AlertManager struct {
	// Scalar fields first for optimal memory layout
	maxAlerts  int
	alertCount int
	running    bool
	lastMinute time.Time

	// Pointer-like fields
	mu           sync.RWMutex
	recentAlerts map[string]time.Time
	channels     []NotificationChannel
	alerts       []*Alert
	config       *AlertConfig
	stopCh       chan struct{}
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig) *AlertManager {
	if config == nil {
		config = DefaultAlertConfig()
	}

	return &AlertManager{
		config:       config,
		channels:     make([]NotificationChannel, 0),
		alerts:       make([]*Alert, 0),
		maxAlerts:    10000,
		recentAlerts: make(map[string]time.Time),
		lastMinute:   time.Now(),
		stopCh:       make(chan struct{}),
	}
}

// AddChannel adds a notification channel
func (am *AlertManager) AddChannel(channel NotificationChannel) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.channels = append(am.channels, channel)
}

// SendAlert sends an alert to all enabled channels
// audit-fix R4-M12: release lock before sending to avoid blocking during retries
func (am *AlertManager) SendAlert(alert *Alert) error {
	am.mu.Lock()

	// Check severity threshold
	if alert.Severity < am.config.MinSeverity {
		am.mu.Unlock()
		return nil
	}

	// Rate limiting
	now := time.Now()
	if now.Sub(am.lastMinute) > time.Minute {
		am.alertCount = 0
		am.lastMinute = now
	}

	if am.alertCount >= am.config.MaxAlertsPerMinute {
		am.mu.Unlock()
		return errors.New("rate limit exceeded")
	}

	// Deduplication
	alertKey := fmt.Sprintf("%s:%s:%s", alert.Type, alert.Source, alert.Title)
	if lastSent, exists := am.recentAlerts[alertKey]; exists {
		if now.Sub(lastSent) < am.config.DeduplicationWindow {
			am.mu.Unlock()
			return nil // Duplicate, skip
		}
	}

	// Set timestamp and ID
	if alert.Timestamp.IsZero() {
		alert.Timestamp = now
	}
	if alert.ID == "" {
		alert.ID = fmt.Sprintf("%d-%s", now.UnixNano(), alert.Type)
	}

	// Store alert
	am.alerts = append(am.alerts, alert)
	if len(am.alerts) > am.maxAlerts {
		am.alerts = am.alerts[1:]
	}

	// Update deduplication map
	am.recentAlerts[alertKey] = now
	am.alertCount++

	// Copy channels and config for sending without lock
	channelsCopy := make([]NotificationChannel, len(am.channels))
	copy(channelsCopy, am.channels)
	maxRetries := am.config.MaxRetries
	retryInterval := am.config.RetryInterval

	am.mu.Unlock()

	// Send to all enabled channels without holding lock
	var lastErr error
	for _, channel := range channelsCopy {
		if channel.IsEnabled() {
			if err := am.sendWithRetryUnlocked(channel, alert, maxRetries, retryInterval); err != nil {
				lastErr = err
			}
		}
	}

	return lastErr
}

// sendWithRetryUnlocked sends an alert with retry logic without requiring lock
// audit-fix R4-M12: separate unlocked version to avoid blocking during retries
func (am *AlertManager) sendWithRetryUnlocked(channel NotificationChannel, alert *Alert, maxRetries int, retryInterval time.Duration) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := channel.Send(alert); err != nil {
			lastErr = err
			time.Sleep(retryInterval)
			continue
		}
		return nil
	}
	return lastErr
}

// GetAlerts returns recent alerts
func (am *AlertManager) GetAlerts(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.alerts) {
		limit = len(am.alerts)
	}

	result := make([]*Alert, limit)
	copy(result, am.alerts[len(am.alerts)-limit:])
	return result
}

// AcknowledgeAlert marks an alert as acknowledged
func (am *AlertManager) AcknowledgeAlert(id string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, alert := range am.alerts {
		if alert.ID == id {
			alert.Acknowledged = true
			return nil
		}
	}
	return errors.New("alert not found")
}

// ResolveAlert marks an alert as resolved
func (am *AlertManager) ResolveAlert(id string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	for _, alert := range am.alerts {
		if alert.ID == id {
			alert.Resolved = true
			alert.ResolvedAt = time.Now()
			return nil
		}
	}
	return errors.New("alert not found")
}

// Start starts the alert manager cleanup routine
func (am *AlertManager) Start() {
	am.mu.Lock()
	if am.running {
		am.mu.Unlock()
		return
	}
	am.running = true
	am.mu.Unlock()

	go am.cleanupLoop()
}

// Stop stops the alert manager and securely closes all notification channels.
// SECURITY FIX A-2: calls Close() on every channel so that EmailChannel can
// zeroize its SMTP password before the process exits or the manager is discarded.
func (am *AlertManager) Stop() {
	am.mu.Lock()
	if !am.running {
		am.mu.Unlock()
		return
	}
	am.running = false
	channelsCopy := make([]NotificationChannel, len(am.channels))
	copy(channelsCopy, am.channels)
	am.mu.Unlock()

	close(am.stopCh)

	for _, ch := range channelsCopy {
		_ = ch.Close()
	}
}

// cleanupLoop periodically cleans up old deduplication entries
func (am *AlertManager) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-am.stopCh:
			return
		case <-ticker.C:
			am.cleanup()
		}
	}
}

// cleanup removes old deduplication entries
func (am *AlertManager) cleanup() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	for key, timestamp := range am.recentAlerts {
		if now.Sub(timestamp) > am.config.DeduplicationWindow*2 {
			delete(am.recentAlerts, key)
		}
	}
}

// ============================================================================
// Email Channel
// ============================================================================

// EmailConfig holds email notification configuration
// SECURITY FIX A-1: Password changed from string to []byte to enable secure
// zeroization. Go strings are immutable and may persist in memory indefinitely,
// leaving SMTP credentials vulnerable to memory-dump attacks.
type EmailConfig struct {
	// Scalar fields grouped for optimal alignment
	Enabled  bool
	UseTLS   bool
	Password []byte // []byte enables zeroization; string does not
	SMTPPort int

	// String fields
	SMTPHost string
	Username string
	From     string

	// Slice fields
	To []string
}

// EmailChannel sends alerts via email
type EmailChannel struct {
	config   *EmailConfig
	template *template.Template
}

// NewEmailChannel creates a new email channel
func NewEmailChannel(config *EmailConfig) *EmailChannel {
	tmpl := template.Must(template.New("email").Parse(`
Subject: [{{.Severity}}] {{.Title}}

Security Alert
==============

Type: {{.Type}}
Severity: {{.Severity}}
Source: {{.Source}}
Time: {{.Timestamp}}

Message:
{{.Message}}

{{if .Details}}
Details:
{{range $key, $value := .Details}}
  {{$key}}: {{$value}}
{{end}}
{{end}}

---
This is an automated alert from Quantaureum Security Monitor.
`))

	return &EmailChannel{
		config:   config,
		template: tmpl,
	}
}

func (e *EmailChannel) Name() string {
	return "email"
}

func (e *EmailChannel) IsEnabled() bool {
	return e.config.Enabled
}

// Close securely zeroizes the SMTP password held in EmailConfig.
// SECURITY FIX A-2: ensures that the []byte password is overwritten with zeros
// when the channel is no longer needed, reducing the window for memory-dump attacks.
func (e *EmailChannel) Close() error {
	if e.config == nil {
		return nil
	}
	// Overwrite password bytes with random data then zeros (three-pass wipe)
	// to mitigate cold-boot and remanence attacks per project crypto conventions.
	for i := range e.config.Password {
		e.config.Password[i] = byte(i) // deterministic non-zero pattern
	}
	for i := range e.config.Password {
		e.config.Password[i] = 0xFF
	}
	for i := range e.config.Password {
		e.config.Password[i] = 0x00
	}
	return nil
}

// sanitizeHeaderField removes \r and \n from a string to prevent SMTP header injection.
// audit-fix R11-M1: alert fields embedded in Subject and other headers must not contain newlines.
func sanitizeHeaderField(s string) string {
	var b bytes.Buffer
	for _, c := range s {
		if c != '\r' && c != '\n' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (e *EmailChannel) Send(alert *Alert) error {
	if !e.config.Enabled {
		return nil
	}

	// audit-fix R11-M1: sanitize fields that are embedded in SMTP headers to prevent
	// header injection via \r\n sequences in alert Title/Message/Source.
	safeAlert := *alert
	safeAlert.Title = sanitizeHeaderField(safeAlert.Title)
	safeAlert.Message = sanitizeHeaderField(safeAlert.Message)
	safeAlert.Source = sanitizeHeaderField(safeAlert.Source)

	var body bytes.Buffer
	if err := e.template.Execute(&body, &safeAlert); err != nil {
		return err
	}

	host := e.config.SMTPHost
	// audit-fix: use net.JoinHostPort for proper IPv6 support
	// This correctly handles both IPv4 and IPv6 addresses
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", e.config.SMTPPort))
	// SECURITY FIX A-1: Convert []byte password to string for smtp.PlainAuth.
	// The temporary string copy is unavoidable (net/smtp API constraint), but
	// the canonical copy in EmailConfig.Password remains a []byte that can be
	// zeroized when the channel is closed or rotated.
	auth := smtp.PlainAuth("", e.config.Username, string(e.config.Password), host)

	// If TLS is required, enforce it (either implicit TLS on 465 or STARTTLS on other ports)
	if e.config.UseTLS {
		// Prefer implicit TLS when using the SMTPS port (465)
		if e.config.SMTPPort == 465 {
			// Implicit TLS
			tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12} // audit-fix R56: explicit MinVersion
			conn, err := tls.Dial("tcp", addr, tlsCfg)
			if err != nil {
				return err
			}
			defer conn.Close()
			client, err := smtp.NewClient(conn, host)
			if err != nil {
				return err
			}
			defer client.Close()
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
			if err := client.Mail(e.config.From); err != nil {
				return err
			}
			for _, rcpt := range e.config.To {
				if err := client.Rcpt(rcpt); err != nil {
					return err
				}
			}
			wc, err := client.Data()
			if err != nil {
				return err
			}
			if _, err := wc.Write(body.Bytes()); err != nil {
				_ = wc.Close()
				return err
			}
			if err := wc.Close(); err != nil {
				return err
			}
			return client.Quit()
		}
		// STARTTLS on submission ports (e.g., 587)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return err
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer client.Close()
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server at %s does not support STARTTLS, refusing to send credentials in cleartext", addr)
		}
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil { // audit-fix R56: explicit MinVersion
			return err
		}
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
		if err := client.Mail(e.config.From); err != nil {
			return err
		}
		for _, rcpt := range e.config.To {
			if err := client.Rcpt(rcpt); err != nil {
				return err
			}
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write(body.Bytes()); err != nil {
			_ = wc.Close()
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	}

	// Opportunistic path (legacy): fall back to net/smtp convenience if TLS is not strictly required
	return smtp.SendMail(addr, auth, e.config.From, e.config.To, body.Bytes())
}

// ============================================================================
// Slack Channel
// ============================================================================

// SlackConfig holds Slack notification configuration
type SlackConfig struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

// SlackChannel sends alerts to Slack
type SlackChannel struct {
	config *SlackConfig
	client *http.Client
}

// NewSlackChannel creates a new Slack channel
func NewSlackChannel(config *SlackConfig) *SlackChannel {
	return &SlackChannel{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackChannel) Name() string {
	return "slack"
}

func (s *SlackChannel) IsEnabled() bool {
	return s.config.Enabled
}

func (s *SlackChannel) Close() error { return nil }

func (s *SlackChannel) Send(alert *Alert) error {
	if !s.config.Enabled {
		return nil
	}

	// Build Slack message
	color := "#36a64f" // Green
	switch alert.Severity {
	case SeverityInfo:
		color = "#36a64f"
	case SeverityWarning:
		color = "#ffcc00"
	case SeverityError:
		color = "#ff6600"
	case SeverityCritical:
		color = "#ff0000"
	}

	payload := map[string]any{
		"channel":  s.config.Channel,
		"username": s.config.Username,
		"attachments": []map[string]any{
			{
				"color": color,
				"title": fmt.Sprintf("[%s] %s", alert.Severity, alert.Title),
				"text":  alert.Message,
				"fields": []map[string]any{
					{"title": "Type", "value": alert.Type, "short": true},
					{"title": "Source", "value": alert.Source, "short": true},
					{"title": "Time", "value": alert.Timestamp.Format(time.RFC3339), "short": true},
				},
				"footer": "Quantaureum Security Monitor",
				"ts":     alert.Timestamp.Unix(),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := s.client.Post(s.config.WebhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

// ============================================================================
// Discord Channel
// ============================================================================

// DiscordConfig holds Discord notification configuration
type DiscordConfig struct {
	Enabled    bool
	Username   string
	WebhookURL string
}

// DiscordChannel sends alerts to Discord
type DiscordChannel struct {
	config *DiscordConfig
	client *http.Client
}

// NewDiscordChannel creates a new Discord channel
func NewDiscordChannel(config *DiscordConfig) *DiscordChannel {
	return &DiscordChannel{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *DiscordChannel) Name() string {
	return "discord"
}

func (d *DiscordChannel) IsEnabled() bool {
	return d.config.Enabled
}

func (d *DiscordChannel) Close() error { return nil }

func (d *DiscordChannel) Send(alert *Alert) error {
	if !d.config.Enabled {
		return nil
	}

	// Build Discord embed
	color := 0x36a64f // Green
	switch alert.Severity {
	case SeverityInfo:
		color = 0x36a64f
	case SeverityWarning:
		color = 0xffcc00
	case SeverityError:
		color = 0xff6600
	case SeverityCritical:
		color = 0xff0000
	}

	payload := map[string]any{
		"username": d.config.Username,
		"embeds": []map[string]any{
			{
				"title":       fmt.Sprintf("[%s] %s", alert.Severity, alert.Title),
				"description": alert.Message,
				"color":       color,
				"fields": []map[string]any{
					{"name": "Type", "value": alert.Type, "inline": true},
					{"name": "Source", "value": alert.Source, "inline": true},
				},
				"timestamp": alert.Timestamp.Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Quantaureum Security Monitor",
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := d.client.Post(d.config.WebhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord returned status %d", resp.StatusCode)
	}

	return nil
}

// ============================================================================
// Webhook Channel (Generic)
// ============================================================================

// WebhookConfig holds generic webhook configuration
type WebhookConfig struct {
	Headers map[string]string
	Enabled bool
	URL     string
	Method  string // POST or PUT
}

// WebhookChannel sends alerts to a generic webhook
type WebhookChannel struct {
	config *WebhookConfig
	client *http.Client
}

// NewWebhookChannel creates a new webhook channel
func NewWebhookChannel(config *WebhookConfig) *WebhookChannel {
	if config.Method == "" {
		config.Method = "POST"
	}
	return &WebhookChannel{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookChannel) Name() string {
	return "webhook"
}

func (w *WebhookChannel) IsEnabled() bool {
	return w.config.Enabled
}

func (w *WebhookChannel) Close() error { return nil }

func (w *WebhookChannel) Send(alert *Alert) error {
	if !w.config.Enabled {
		return nil
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(w.config.Method, w.config.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// ============================================================================
// PagerDuty Channel
// ============================================================================

// PagerDutyConfig holds PagerDuty notification configuration
type PagerDutyConfig struct {
	Enabled     bool
	RoutingKey  string // Integration/Routing key from PagerDuty
	ServiceName string
	Environment string
}

// PagerDutyChannel sends alerts to PagerDuty
type PagerDutyChannel struct {
	config *PagerDutyConfig
	client *http.Client
}

// NewPagerDutyChannel creates a new PagerDuty channel
func NewPagerDutyChannel(config *PagerDutyConfig) *PagerDutyChannel {
	return &PagerDutyChannel{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *PagerDutyChannel) Name() string {
	return "pagerduty"
}

func (p *PagerDutyChannel) IsEnabled() bool {
	return p.config.Enabled && p.config.RoutingKey != ""
}

func (p *PagerDutyChannel) Close() error { return nil }

func (p *PagerDutyChannel) Send(alert *Alert) error {
	if !p.IsEnabled() {
		return nil
	}

	// Map severity to PagerDuty severity
	pdSeverity := "info"
	switch alert.Severity {
	case SeverityInfo:
		pdSeverity = "info"
	case SeverityWarning:
		pdSeverity = "warning"
	case SeverityError:
		pdSeverity = "error"
	case SeverityCritical:
		pdSeverity = "critical"
	}

	// Build PagerDuty Events API v2 payload
	payload := map[string]any{
		"routing_key":  p.config.RoutingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("%s-%s-%s", alert.Type, alert.Source, alert.ID),
		"payload": map[string]any{
			"summary":   fmt.Sprintf("[%s] %s", alert.Severity, alert.Title),
			"source":    alert.Source,
			"severity":  pdSeverity,
			"timestamp": alert.Timestamp.Format(time.RFC3339),
			"component": p.config.ServiceName,
			"group":     alert.Type,
			"class":     "security",
			"custom_details": map[string]any{
				"message":     alert.Message,
				"environment": p.config.Environment,
				"alert_id":    alert.ID,
				"details":     alert.Details,
			},
		},
		"links": []map[string]string{
			{
				"href": "https://quantaureum.io/alerts",
				"text": "View in Dashboard",
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// PagerDuty Events API v2 endpoint
	resp, err := p.client.Post(
		"https://events.pagerduty.com/v2/enqueue",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pagerduty returned status %d", resp.StatusCode)
	}

	return nil
}

// ResolveAlert resolves an alert in PagerDuty
func (p *PagerDutyChannel) ResolveAlert(alert *Alert) error {
	if !p.IsEnabled() {
		return nil
	}

	payload := map[string]any{
		"routing_key":  p.config.RoutingKey,
		"event_action": "resolve",
		"dedup_key":    fmt.Sprintf("%s-%s-%s", alert.Type, alert.Source, alert.ID),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := p.client.Post(
		"https://events.pagerduty.com/v2/enqueue",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// AcknowledgeAlert acknowledges an alert in PagerDuty
func (p *PagerDutyChannel) AcknowledgeAlert(alert *Alert) error {
	if !p.IsEnabled() {
		return nil
	}

	payload := map[string]any{
		"routing_key":  p.config.RoutingKey,
		"event_action": "acknowledge",
		"dedup_key":    fmt.Sprintf("%s-%s-%s", alert.Type, alert.Source, alert.ID),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := p.client.Post(
		"https://events.pagerduty.com/v2/enqueue",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// ============================================================================
// Console Channel (for logging/debugging)
// ============================================================================

// ConsoleChannel prints alerts to console
type ConsoleChannel struct {
	enabled bool
}

// NewConsoleChannel creates a new console channel
func NewConsoleChannel(enabled bool) *ConsoleChannel {
	return &ConsoleChannel{enabled: enabled}
}

func (c *ConsoleChannel) Name() string {
	return "console"
}

func (c *ConsoleChannel) IsEnabled() bool {
	return c.enabled
}

func (c *ConsoleChannel) Close() error { return nil }

func (c *ConsoleChannel) Send(alert *Alert) error {
	if !c.enabled {
		return nil
	}

	slog.Warn("alert received",
		"severity", alert.Severity,
		"type", alert.Type,
		"message", alert.Message,
		"source", alert.Source,
		"timestamp", alert.Timestamp.Format("2006-01-02 15:04:05"),
	)

	return nil
}
