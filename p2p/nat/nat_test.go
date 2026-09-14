// Quantaureum Node source, version 1.0.0.
package nat

import (
	"net"
	"testing"
	"time"
)

func TestExtIP(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	if iface.String() != "ExtIP(198.51.100.10)" {
		t.Errorf("ExtIP.String() = %q, want %q", iface.String(), "ExtIP(198.51.100.10)")
	}
}

func TestExtIPExternalIP(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	extIP, err := iface.ExternalIP()
	if err != nil {
		t.Fatalf("ExternalIP failed: %v", err)
	}
	if !extIP.Equal(ip) {
		t.Errorf("ExternalIP = %v, want %v", extIP, ip)
	}
}

func TestExtIPAddMapping(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	port, err := iface.AddMapping("tcp", 9000, 9000, "test", time.Hour)
	if err != nil {
		t.Errorf("AddMapping should not fail for ExtIP: %v", err)
	}
	if port != 9000 {
		t.Errorf("port = %d, want 9000", port)
	}
}

func TestExtIPDeleteMapping(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	err := iface.DeleteMapping("tcp", 9000, 9000)
	if err != nil {
		t.Errorf("DeleteMapping should not fail for ExtIP: %v", err)
	}
}

func TestUPnP(t *testing.T) {
	iface := UPnP()
	if iface == nil {
		t.Fatal("UPnP returned nil")
	}
	if iface.String() != "UPnP" {
		t.Errorf("String() = %q, want %q", iface.String(), "UPnP")
	}
}

func TestUPnPAddMapping(t *testing.T) {
	iface := UPnP()

	_, err := iface.AddMapping("tcp", 9000, 9000, "test", time.Hour)
	if err != nil {
		t.Fatalf("AddMapping failed: %v", err)
	}
}

func TestUPnPDeleteMapping(t *testing.T) {
	iface := UPnP()
	_, _ = iface.AddMapping("tcp", 9000, 9000, "test", time.Hour)

	err := iface.DeleteMapping("tcp", 9000, 9000)
	if err != nil {
		t.Fatalf("DeleteMapping failed: %v", err)
	}
}

func TestPMP(t *testing.T) {
	gateway := net.ParseIP("192.168.1.1")
	iface := PMP(gateway)
	if iface == nil {
		t.Fatal("PMP returned nil")
	}
	expected := "NAT-PMP(192.168.1.1)"
	if iface.String() != expected {
		t.Errorf("String() = %q, want %q", iface.String(), expected)
	}
}

func TestPMPAddMapping(t *testing.T) {
	gateway := net.ParseIP("192.168.1.1")
	iface := PMP(gateway)

	_, err := iface.AddMapping("tcp", 9000, 9000, "test", time.Hour)
	if err != nil {
		t.Fatalf("AddMapping failed: %v", err)
	}
}

func TestPMPDeleteMapping(t *testing.T) {
	gateway := net.ParseIP("192.168.1.1")
	iface := PMP(gateway)
	_, _ = iface.AddMapping("tcp", 9000, 9000, "test", time.Hour)

	err := iface.DeleteMapping("tcp", 9000, 9000)
	if err != nil {
		t.Fatalf("DeleteMapping failed: %v", err)
	}
}

func TestAny(t *testing.T) {
	iface := Any()
	if iface == nil {
		t.Fatal("Any returned nil")
	}
}

func TestAnyString(t *testing.T) {
	iface := Any()
	s := iface.String()
	if s == "" {
		t.Error("String should not be empty")
	}
}

func TestMappingIsExpired(t *testing.T) {
	m := &Mapping{
		Protocol: "tcp",
		ExtPort:  9000,
		IntPort:  9000,
		Name:     "test",
		Lifetime: time.Hour,
		Created:  time.Now(),
	}

	if m.IsExpired() {
		t.Error("mapping should not be expired")
	}

	m.Created = time.Now().Add(-2 * time.Hour)
	if !m.IsExpired() {
		t.Error("mapping should be expired")
	}
}

func TestNewMap(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	m := NewMap(iface)
	if m == nil {
		t.Fatal("NewMap returned nil")
	}
	m.Close()
}

func TestMapAdd(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	m := NewMap(iface)
	defer m.Close()

	err := m.Add("tcp", 9000, 9000, "test")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
}

func TestMapRemove(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	m := NewMap(iface)
	defer m.Close()

	_ = m.Add("tcp", 9000, 9000, "test")
	err := m.Remove("tcp", 9000, 9000)
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
}

func TestMapClose(t *testing.T) {
	ip := net.ParseIP("198.51.100.10")
	iface := ExtIP(ip)

	m := NewMap(iface)
	m.Close()
	// Should not panic on double close
}

func TestSetExternalIPDetectTarget(t *testing.T) {
	// Valid address
	SetExternalIPDetectTarget("198.51.100.10:80")

	// Empty string should be ignored
	SetExternalIPDetectTarget("")

	// Private IP should be rejected
	SetExternalIPDetectTarget("192.168.1.1:80")

	// Malformed address should be ignored
	SetExternalIPDetectTarget("not-valid")
}

func TestInterfaceType(t *testing.T) {
	// Verify Interface type is properly defined
	var _ Interface = ExtIP(net.ParseIP("198.51.100.10"))
	var _ Interface = UPnP()
	var _ Interface = PMP(net.ParseIP("192.168.1.1"))
	var _ Interface = Any()
}
