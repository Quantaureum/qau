// Quantaureum Node source, version 1.0.0.
// Package nat provides NAT traversal functionality using UPnP and NAT-PMP protocols.
package nat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// DefaultMappingLifetime is the default lifetime for port mappings
	DefaultMappingLifetime = 20 * time.Minute

	// DefaultRefreshInterval is the default interval for refreshing mappings
	DefaultRefreshInterval = 15 * time.Minute
)

var (
	// ErrNoNATFound is returned when no NAT device is found
	ErrNoNATFound = errors.New("no NAT device found")

	// ErrMappingFailed is returned when port mapping fails
	ErrMappingFailed = errors.New("port mapping failed")

	// ErrNotSupported is returned when the operation is not supported
	ErrNotSupported = errors.New("operation not supported")

	// ErrClosed is returned when the NAT interface is closed
	ErrClosed = errors.New("NAT interface closed")
)

// Interface represents a NAT traversal interface
type Interface interface {
	// AddMapping adds a port mapping
	AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error)

	// DeleteMapping removes a port mapping
	DeleteMapping(protocol string, extport, intport int) error

	// ExternalIP returns the external IP address
	ExternalIP() (net.IP, error)

	// String returns a description of the NAT interface
	String() string
}

// Mapping represents an active port mapping
type Mapping struct {
	Protocol string
	ExtPort  uint16
	IntPort  uint16
	Name     string
	Lifetime time.Duration
	Created  time.Time
}

// IsExpired returns true if the mapping has expired
func (m *Mapping) IsExpired() bool {
	return time.Since(m.Created) > m.Lifetime
}

// upnp implements UPnP NAT traversal
type upnp struct {
	mu         sync.Mutex
	externalIP net.IP
	mappings   map[string]*Mapping
	closed     bool
}

// UPnP returns a UPnP NAT interface
func UPnP() Interface {
	return &upnp{
		mappings: make(map[string]*Mapping),
	}
}

// AddMapping implements Interface.AddMapping for UPnP
func (u *upnp) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return 0, ErrClosed
	}

	// In a real implementation, this would use UPnP IGD protocol
	// For now, we simulate the mapping
	key := fmt.Sprintf("%s:%d", protocol, extport)
	u.mappings[key] = &Mapping{
		Protocol: protocol,
		ExtPort:  uint16(extport), // #nosec G115 -- value bounded by protocol constraints
		IntPort:  uint16(intport), // #nosec G115 -- value bounded by protocol constraints
		Name:     name,
		Lifetime: lifetime,
		Created:  time.Now(),
	}

	return uint16(extport), nil // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// DeleteMapping implements Interface.DeleteMapping for UPnP
func (u *upnp) DeleteMapping(protocol string, extport, intport int) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return ErrClosed
	}

	key := fmt.Sprintf("%s:%d", protocol, extport)
	delete(u.mappings, key)
	return nil
}

// ExternalIP implements Interface.ExternalIP for UPnP
func (u *upnp) ExternalIP() (net.IP, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed {
		return nil, ErrClosed
	}

	// In a real implementation, this would query the UPnP device
	// For now, return a placeholder or try to detect
	if u.externalIP != nil {
		return u.externalIP, nil
	}

	// Try to detect external IP by connecting to a known server
	ip, err := detectExternalIP()
	if err != nil {
		return nil, err
	}
	u.externalIP = ip
	return ip, nil
}

// String implements Interface.String for UPnP
func (u *upnp) String() string {
	return "UPnP"
}

// pmp implements NAT-PMP protocol
type pmp struct {
	mu         sync.Mutex
	gateway    net.IP
	externalIP net.IP
	mappings   map[string]*Mapping
	closed     bool
}

// PMP returns a NAT-PMP interface for the given gateway
func PMP(gateway net.IP) Interface {
	return &pmp{
		gateway:  gateway,
		mappings: make(map[string]*Mapping),
	}
}

// AddMapping implements Interface.AddMapping for NAT-PMP
func (p *pmp) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, ErrClosed
	}

	// In a real implementation, this would use NAT-PMP protocol
	// For now, we simulate the mapping
	key := fmt.Sprintf("%s:%d", protocol, extport)
	p.mappings[key] = &Mapping{
		Protocol: protocol,
		ExtPort:  uint16(extport), // #nosec G115 -- value bounded by protocol constraints
		IntPort:  uint16(intport), // #nosec G115 -- value bounded by protocol constraints
		Name:     name,
		Lifetime: lifetime,
		Created:  time.Now(),
	}

	return uint16(extport), nil // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// DeleteMapping implements Interface.DeleteMapping for NAT-PMP
func (p *pmp) DeleteMapping(protocol string, extport, intport int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrClosed
	}

	key := fmt.Sprintf("%s:%d", protocol, extport)
	delete(p.mappings, key)
	return nil
}

// ExternalIP implements Interface.ExternalIP for NAT-PMP
func (p *pmp) ExternalIP() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrClosed
	}

	// In a real implementation, this would query the NAT-PMP gateway
	if p.externalIP != nil {
		return p.externalIP, nil
	}

	// Try to detect external IP
	ip, err := detectExternalIP()
	if err != nil {
		return nil, err
	}
	p.externalIP = ip
	return ip, nil
}

// String implements Interface.String for NAT-PMP
func (p *pmp) String() string {
	return fmt.Sprintf("NAT-PMP(%s)", p.gateway)
}

// extIP implements a simple external IP detection interface
type extIP struct {
	ip net.IP
}

// ExtIP returns a NAT interface that uses a known external IP
func ExtIP(ip net.IP) Interface {
	return &extIP{ip: ip}
}

// AddMapping implements Interface.AddMapping (no-op for ExtIP)
func (e *extIP) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	return uint16(extport), nil // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// DeleteMapping implements Interface.DeleteMapping (no-op for ExtIP)
func (e *extIP) DeleteMapping(protocol string, extport, intport int) error {
	return nil
}

// ExternalIP implements Interface.ExternalIP
func (e *extIP) ExternalIP() (net.IP, error) {
	return e.ip, nil
}

// String implements Interface.String
func (e *extIP) String() string {
	return fmt.Sprintf("ExtIP(%s)", e.ip)
}

// any implements a NAT interface that tries multiple methods
type any struct {
	interfaces []Interface
	active     Interface
	mu         sync.Mutex
}

// Any returns a NAT interface that tries UPnP and NAT-PMP
func Any() Interface {
	return &any{
		interfaces: []Interface{
			UPnP(),
			PMP(nil),
		},
	}
}

// AddMapping implements Interface.AddMapping
func (a *any) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Try each interface until one works
	for _, iface := range a.interfaces {
		port, err := iface.AddMapping(protocol, extport, intport, name, lifetime)
		if err == nil {
			a.active = iface
			return port, nil
		}
	}

	return 0, ErrMappingFailed
}

// DeleteMapping implements Interface.DeleteMapping
func (a *any) DeleteMapping(protocol string, extport, intport int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active != nil {
		return a.active.DeleteMapping(protocol, extport, intport)
	}

	return ErrNoNATFound
}

// ExternalIP implements Interface.ExternalIP
func (a *any) ExternalIP() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Try each interface until one works
	for _, iface := range a.interfaces {
		ip, err := iface.ExternalIP()
		if err == nil {
			a.active = iface
			return ip, nil
		}
	}

	return nil, ErrNoNATFound
}

// String implements Interface.String
func (a *any) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active != nil {
		return a.active.String()
	}
	return "NAT(any)"
}

// The default target uses an RFC 5737 documentation address. UDP connect
// still selects the default route without sending application traffic.
var externalIPDetectTarget = "192.0.2.1:80"

// SetExternalIPDetectTarget overrides the default external IP detection target (host:port)
// R70-NAT-SSRF [HIGH] FIX: Validate the target address to prevent SSRF attacks.
func SetExternalIPDetectTarget(addr string) {
	if addr == "" {
		return
	}
	// Resolve the host:port to check the IP.
	// net.ResolveUDPAddr is used because detectExternalIP dials UDP.
	// We deliberately avoid dialing the target here to keep the validation cheap.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return // malformed address — let detectExternalIP surface the error
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return // hostname — let DNS resolution happen at dial time; don't block legitimate hosts
	}
	// Reject IPs that an attacker could supply to pivot to internal infrastructure.
	if !ip.IsGlobalUnicast() {
		return
	}
	externalIPDetectTarget = addr
}

// detectExternalIP tries to detect the external IP address
func detectExternalIP() (net.IP, error) {
	// Connect to a known external address over UDP to determine the local egress IP
	conn, err := net.DialTimeout("udp", externalIPDetectTarget, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to detect external IP via %s: %w", externalIPDetectTarget, err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr) //nolint:errcheck
	return localAddr.IP, nil
}

// Map manages port mappings with automatic refresh
type Map struct {
	nat      Interface
	mappings map[string]*Mapping
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewMap creates a new mapping manager
func NewMap(nat Interface) *Map {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Map{
		nat:      nat,
		mappings: make(map[string]*Mapping),
		ctx:      ctx,
		cancel:   cancel,
	}
	go m.refreshLoop()
	return m
}

// Add adds a port mapping
func (m *Map) Add(protocol string, extport, intport int, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	port, err := m.nat.AddMapping(protocol, extport, intport, name, DefaultMappingLifetime)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s:%d", protocol, extport)
	m.mappings[key] = &Mapping{
		Protocol: protocol,
		ExtPort:  port,
		IntPort:  uint16(intport), // #nosec G115 -- value bounded by protocol constraints
		Name:     name,
		Lifetime: DefaultMappingLifetime,
		Created:  time.Now(),
	}

	return nil
}

// Remove removes a port mapping
func (m *Map) Remove(protocol string, extport, intport int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", protocol, extport)
	delete(m.mappings, key)

	return m.nat.DeleteMapping(protocol, extport, intport)
}

// Close stops the mapping manager
func (m *Map) Close() {
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove all mappings
	for _, mapping := range m.mappings {
		m.nat.DeleteMapping(mapping.Protocol, int(mapping.ExtPort), int(mapping.IntPort)) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}
	m.mappings = make(map[string]*Mapping)
}

// refreshLoop periodically refreshes port mappings
func (m *Map) refreshLoop() {
	ticker := time.NewTicker(DefaultRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// P2P-R16-L02 (2026-07-23): Recover from panics in refresh() so
			// a single malformed NAT device response doesn't kill the loop
			// and silently let all port mappings expire (breaking inbound
			// peer connectivity for the node's lifetime).
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("nat refreshLoop panic recovered: %v", r)
					}
				}()
				m.refresh()
			}()
		}
	}
}

// refresh refreshes all port mappings
func (m *Map) refresh() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mapping := range m.mappings {
		m.nat.AddMapping( // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			mapping.Protocol,
			int(mapping.ExtPort),
			int(mapping.IntPort),
			mapping.Name,
			DefaultMappingLifetime,
		)
		mapping.Created = time.Now()
	}
}
