// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"testing"
)

func TestGasMeter_Consume(t *testing.T) {
	tests := []struct {
		name         string
		limit        uint64
		consume      uint64
		expectErr    error
		expectedUsed uint64
	}{
		{name: "Consume gas within limit - succeeds", limit: 1000, consume: 500, expectErr: nil, expectedUsed: 500},
		{name: "Consume gas exceeding limit - triggers out-of-gas", limit: 100, consume: 200, expectErr: ErrOutOfGas, expectedUsed: 100},
		{name: "Consume with zero - succeeds", limit: 1000, consume: 0, expectErr: nil, expectedUsed: 0},
		{name: "Consume exactly remaining gas - succeeds", limit: 100, consume: 100, expectErr: nil, expectedUsed: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := NewGasMeter(tt.limit)
			err := gm.Consume(tt.consume)
			if tt.expectErr != nil {
				if err != tt.expectErr {
					t.Errorf("expected error %v, got %v", tt.expectErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if gm.Used() != tt.expectedUsed {
				t.Errorf("expected used gas %d, got %d", tt.expectedUsed, gm.Used())
			}
		})
	}
}

func TestGasMeter_ConsumeWithRefund(t *testing.T) {
	tests := []struct {
		name         string
		limit        uint64
		consume      uint64
		refund       uint64
		expectErr    error
		expectedUsed uint64
	}{
		{name: "Track refunds correctly", limit: 1000, consume: 100, refund: 10, expectErr: nil, expectedUsed: 100},
		{name: "Refund applied on revert - refunds are tracked", limit: 1000, consume: 500, refund: 50, expectErr: nil, expectedUsed: 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := NewGasMeter(tt.limit)
			err := gm.ConsumeWithRefund(tt.consume, tt.refund)
			if tt.expectErr != nil {
				if err != tt.expectErr {
					t.Errorf("expected error %v, got %v", tt.expectErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if gm.Used() != tt.expectedUsed {
				t.Errorf("expected used gas %d, got %d", tt.expectedUsed, gm.Used())
			}
		})
	}
}

func TestGasMeter_Return(t *testing.T) {
	tests := []struct {
		name         string
		initialLimit uint64
		consumeFirst uint64
		returnAmount uint64
		expectedUsed uint64
	}{
		{name: "Return unused gas", initialLimit: 1000, consumeFirst: 500, returnAmount: 200, expectedUsed: 300},
		{name: "Return more than consumed - should cap at consumed", initialLimit: 1000, consumeFirst: 100, returnAmount: 500, expectedUsed: 0},
		{name: "Return zero - no change", initialLimit: 1000, consumeFirst: 300, returnAmount: 0, expectedUsed: 300},
		{name: "Consume all then return - reduces used (sub-call gas return)", initialLimit: 100, consumeFirst: 100, returnAmount: 50, expectedUsed: 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := NewGasMeter(tt.initialLimit)
			gm.Consume(tt.consumeFirst)
			gm.Return(tt.returnAmount)
			if gm.Used() != tt.expectedUsed {
				t.Errorf("expected used gas %d, got %d", tt.expectedUsed, gm.Used())
			}
		})
	}
}

func TestGasMeter_RefundAmount(t *testing.T) {
	tests := []struct {
		name           string
		limit          uint64
		setup          func(*GasMeter)
		expectedRefund uint64
	}{
		{name: "Refund starts at 0", limit: 1000, setup: func(gm *GasMeter) {}, expectedRefund: 0},
		{name: "Refund accumulates correctly", limit: 1000, setup: func(gm *GasMeter) { gm.ConsumeWithRefund(100, 10); gm.ConsumeWithRefund(100, 20) }, expectedRefund: 30},
		{name: "EIP-3529 cap applied - max 50% of consumed gas", limit: 1000, setup: func(gm *GasMeter) { gm.ConsumeWithRefund(200, 150) }, expectedRefund: 40},
		{name: "EIP-3529 cap with partial refund - no cap needed", limit: 1000, setup: func(gm *GasMeter) { gm.ConsumeWithRefund(200, 30) }, expectedRefund: 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := NewGasMeter(tt.limit)
			tt.setup(gm)
			refund := gm.RefundAmount()
			if refund != tt.expectedRefund {
				t.Errorf("expected refund %d, got %d", tt.expectedRefund, refund)
			}
		})
	}
}

func TestGasMeter_FinalUsed(t *testing.T) {
	t.Run("FinalUsed returns gas after refund deduction", func(t *testing.T) {
		gm := NewGasMeter(1000)
		gm.ConsumeWithRefund(500, 100)
		finalUsed := gm.FinalUsed()
		if finalUsed != 400 {
			t.Errorf("expected final used 400, got %d", finalUsed)
		}
	})
}

func TestGasMeter_Reset(t *testing.T) {
	t.Run("Reset clears all state", func(t *testing.T) {
		gm := NewGasMeter(1000)
		gm.ConsumeWithRefund(500, 50)
		gm.Reset(2000)
		if gm.Used() != 0 {
			t.Errorf("expected 0 used after reset, got %d", gm.Used())
		}
		if gm.Remaining() != 2000 {
			t.Errorf("expected remaining 2000, got %d", gm.Remaining())
		}
		if gm.RefundAmount() != 0 {
			t.Errorf("expected 0 refund after reset, got %d", gm.RefundAmount())
		}
	})
}

func TestGasMeter_Limit(t *testing.T) {
	t.Run("Limit returns correct value", func(t *testing.T) {
		gm := NewGasMeter(5000)
		if gm.Limit() != 5000 {
			t.Errorf("expected limit 5000, got %d", gm.Limit())
		}
	})
}

func TestGasMeter_Remaining(t *testing.T) {
	tests := []struct {
		name           string
		limit          uint64
		consume        uint64
		expectedRemain uint64
	}{
		{name: "Full remaining", limit: 1000, consume: 0, expectedRemain: 1000},
		{name: "Partial remaining", limit: 1000, consume: 300, expectedRemain: 700},
		{name: "No remaining", limit: 100, consume: 100, expectedRemain: 0},
		{name: "Empty after out-of-gas", limit: 100, consume: 200, expectedRemain: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := NewGasMeter(tt.limit)
			gm.Consume(tt.consume)
			if gm.Remaining() != tt.expectedRemain {
				t.Errorf("expected remaining %d, got %d", tt.expectedRemain, gm.Remaining())
			}
		})
	}
}

func TestGasMeter_Clone(t *testing.T) {
	t.Run("Clone creates independent copy", func(t *testing.T) {
		gm := NewGasMeter(1000)
		gm.ConsumeWithRefund(500, 50)
		clone := gm.Clone()
		if clone.Used() != gm.Used() {
			t.Errorf("clone used does not match original")
		}
		if clone.RefundAmount() != gm.RefundAmount() {
			t.Errorf("clone refund does not match original")
		}
		if clone.Limit() != gm.Limit() {
			t.Errorf("clone limit does not match original")
		}
	})
}

func TestGasMeter_Snapshot(t *testing.T) {
	t.Run("Snapshot and revert work correctly", func(t *testing.T) {
		gm := NewGasMeter(1000)
		gm.ConsumeWithRefund(300, 30)
		snapshot := gm.Snapshot()
		gm.ConsumeWithRefund(200, 20)
		if gm.Used() != 500 {
			t.Errorf("expected 500 used before revert, got %d", gm.Used())
		}
		gm.Revert(snapshot)
		if gm.Used() != 300 {
			t.Errorf("expected 300 used after revert, got %d", gm.Used())
		}
	})
}

func TestAccessList_AddAddress(t *testing.T) {
	tests := []struct {
		name       string
		addresses  []Address
		expectCold []bool
	}{
		{name: "Add new address marks it as cold", addresses: []Address{{0x01}, {0x02}}, expectCold: []bool{true, true}},
		{name: "Adding same address again is idempotent", addresses: []Address{{0x01}, {0x01}, {0x01}}, expectCold: []bool{true, false, false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			al := NewAccessList()
			for i, addr := range tt.addresses {
				wasCold := al.AddAddress(addr)
				if wasCold != tt.expectCold[i] {
					t.Errorf("AddAddress(%x) = %v, want %v", addr, wasCold, tt.expectCold[i])
				}
			}
			if !al.IsAddressWarm(tt.addresses[len(tt.addresses)-1]) {
				t.Error("address should be warm after additions")
			}
		})
	}
}

func TestAccessList_AddSlot(t *testing.T) {
	addr := Address{0x01}
	slot1 := Hash{0x01}

	tests := []struct {
		name           string
		setup          func(*AccessList)
		addr           Address
		slot           Hash
		expectAddrCold bool
		expectSlotCold bool
	}{
		{name: "Add new slot marks it as cold", setup: func(al *AccessList) { al.AddAddress(addr) }, addr: addr, slot: slot1, expectAddrCold: false, expectSlotCold: true},
		{name: "Adding same slot again is idempotent", setup: func(al *AccessList) { al.AddSlot(addr, slot1) }, addr: addr, slot: slot1, expectAddrCold: false, expectSlotCold: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			al := NewAccessList()
			tt.setup(al)
			addrCold, slotCold := al.AddSlot(tt.addr, tt.slot)
			if addrCold != tt.expectAddrCold {
				t.Errorf("addrCold = %v, want %v", addrCold, tt.expectAddrCold)
			}
			if slotCold != tt.expectSlotCold {
				t.Errorf("slotCold = %v, want %v", slotCold, tt.expectSlotCold)
			}
		})
	}
}

func TestAccessList_Copy(t *testing.T) {
	t.Run("Copy creates deep copy", func(t *testing.T) {
		al := NewAccessList()
		addr := Address{0x01}
		slot := Hash{0x01}
		al.AddAddress(addr)
		al.AddSlot(addr, slot)
		copy := al.Copy()
		if !copy.IsAddressWarm(addr) {
			t.Error("copy should have warm address")
		}
		if !copy.IsSlotWarm(addr, slot) {
			t.Error("copy should have warm slot")
		}
	})
}

func TestAccessList_Clear(t *testing.T) {
	t.Run("Clear resets all state", func(t *testing.T) {
		al := NewAccessList()
		al.AddAddress(Address{0x01})
		al.AddSlot(Address{0x01}, Hash{0x01})
		al.Clear()
		if al.AddressCount() != 0 {
			t.Errorf("expected 0 addresses, got %d", al.AddressCount())
		}
		if al.SlotCount() != 0 {
			t.Errorf("expected 0 slots, got %d", al.SlotCount())
		}
	})
}

func TestAccessList_Counts(t *testing.T) {
	t.Run("AddressCount returns correct count", func(t *testing.T) {
		al := NewAccessList()
		al.AddAddress(Address{0x01})
		al.AddAddress(Address{0x02})
		al.AddAddress(Address{0x01})
		if al.AddressCount() != 2 {
			t.Errorf("expected 2 addresses, got %d", al.AddressCount())
		}
	})

	t.Run("SlotCount returns correct count", func(t *testing.T) {
		al := NewAccessList()
		addr := Address{0x01}
		al.AddSlot(addr, Hash{0x01})
		al.AddSlot(addr, Hash{0x02})
		al.AddSlot(addr, Hash{0x01})
		if al.SlotCount() != 2 {
			t.Errorf("expected 2 slots, got %d", al.SlotCount())
		}
	})
}

func TestAccessList_IsWarm(t *testing.T) {
	addr1 := Address{0x01}
	slot1 := Hash{0x01}

	t.Run("IsAddressWarm returns false for cold address", func(t *testing.T) {
		al := NewAccessList()
		if al.IsAddressWarm(addr1) {
			t.Error("expected false for cold address")
		}
	})

	t.Run("IsAddressWarm returns true for warm address", func(t *testing.T) {
		al := NewAccessList()
		al.AddAddress(addr1)
		if !al.IsAddressWarm(addr1) {
			t.Error("expected true for warm address")
		}
	})

	t.Run("IsSlotWarm returns false for cold slot", func(t *testing.T) {
		al := NewAccessList()
		if al.IsSlotWarm(addr1, slot1) {
			t.Error("expected false for cold slot")
		}
	})

	t.Run("IsSlotWarm returns true for warm slot", func(t *testing.T) {
		al := NewAccessList()
		al.AddSlot(addr1, slot1)
		if !al.IsSlotWarm(addr1, slot1) {
			t.Error("expected true for warm slot")
		}
	})
}

func TestGasMeter_ConsumeSLoad(t *testing.T) {
	t.Run("First SLOAD is cold (expensive)", func(t *testing.T) {
		gm := NewGasMeter(10000)
		addr := Address{0x01}
		slot := Hash{0x01}
		err := gm.ConsumeSLoad(addr, slot)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if gm.Used() != GasColdSLoad {
			t.Errorf("expected used %d, got %d", GasColdSLoad, gm.Used())
		}
	})

	t.Run("Second SLOAD to same slot is warm (cheaper)", func(t *testing.T) {
		gm := NewGasMeter(10000)
		addr := Address{0x01}
		slot := Hash{0x01}
		gm.ConsumeSLoad(addr, slot)
		gm.ConsumeSLoad(addr, slot)
		if gm.Used() != GasColdSLoad+GasWarmSLoad {
			t.Errorf("expected used %d, got %d", GasColdSLoad+GasWarmSLoad, gm.Used())
		}
	})
}

func TestGasMeter_ConsumeAccountAccess(t *testing.T) {
	t.Run("First account access is cold", func(t *testing.T) {
		gm := NewGasMeter(10000)
		addr := Address{0x01}
		err := gm.ConsumeAccountAccess(addr)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if gm.Used() != GasColdAccountAccess {
			t.Errorf("expected used %d, got %d", GasColdAccountAccess, gm.Used())
		}
	})

	t.Run("Repeat account access is warm", func(t *testing.T) {
		gm := NewGasMeter(10000)
		addr := Address{0x01}
		gm.ConsumeAccountAccess(addr)
		gm.ConsumeAccountAccess(addr)
		if gm.Used() != GasColdAccountAccess+GasWarmAccountAccess {
			t.Errorf("expected used %d, got %d", GasColdAccountAccess+GasWarmAccountAccess, gm.Used())
		}
	})
}

func TestGasMeter_ConsumeCall(t *testing.T) {
	t.Run("Call with value transfer costs more", func(t *testing.T) {
		gm := NewGasMeter(50000)
		addr := Address{0x01}
		cost, err := gm.ConsumeCall(addr, true, false)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		expected := GasColdAccountAccess + GasCallValue
		if cost != expected {
			t.Errorf("expected cost %d, got %d", expected, cost)
		}
	})

	t.Run("Call to new account with value", func(t *testing.T) {
		gm := NewGasMeter(50000)
		addr := Address{0x01}
		cost, err := gm.ConsumeCall(addr, true, true)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		expected := GasColdAccountAccess + GasCallValue + GasCallNewAccount
		if cost != expected {
			t.Errorf("expected cost %d, got %d", expected, cost)
		}
	})
}

func TestGasMeter_PreloadAccessList(t *testing.T) {
	t.Run("Preload addresses and slots", func(t *testing.T) {
		gm := NewGasMeter(100000)
		addresses := []Address{{0x01}, {0x02}}
		slots := map[Address][]Hash{
			{0x01}: {Hash{0x01}, Hash{0x02}},
			{0x02}: {Hash{0x03}},
		}
		cost := gm.PreloadAccessList(addresses, slots)
		expected := 2*GasAccessListAddress + 3*GasAccessListSlot
		if cost != expected {
			t.Errorf("expected cost %d, got %d", expected, cost)
		}
	})
}

func TestCalculateMemoryGas(t *testing.T) {
	tests := []struct {
		name     string
		current  uint64
		new      uint64
		expected uint64
	}{
		{name: "No expansion", current: 100, new: 50, expected: 0},
		{name: "Same size", current: 100, new: 100, expected: 0},
		{name: "Expansion costs gas", current: 0, new: 64, expected: 2*GasMemory + (2*2)/512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateMemoryGas(tt.current, tt.new)
			if cost != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, cost)
			}
		})
	}
}

func TestCalculateCopyGas(t *testing.T) {
	tests := []struct {
		name     string
		size     uint64
		expected uint64
	}{
		{name: "Zero size", size: 0, expected: 0},
		{name: "One word", size: 32, expected: 1 * GasCopy},
		{name: "Two words", size: 64, expected: 2 * GasCopy},
		{name: "Partial word rounds up", size: 33, expected: 2 * GasCopy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateCopyGas(tt.size)
			if cost != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, cost)
			}
		})
	}
}

func TestCalculateExpGas(t *testing.T) {
	tests := []struct {
		name          string
		exponentBytes int
		expected      uint64
	}{
		{name: "Zero bytes", exponentBytes: 0, expected: GasExp},
		{name: "One byte", exponentBytes: 1, expected: GasExp + 1*GasExpByte},
		{name: "32 bytes (max)", exponentBytes: 32, expected: GasExp + 32*GasExpByte},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateExpGas(tt.exponentBytes)
			if cost != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, cost)
			}
		})
	}
}

func TestCalculateSHA3Gas(t *testing.T) {
	tests := []struct {
		name     string
		size     uint64
		expected uint64
	}{
		{name: "Zero size", size: 0, expected: GasSHA3},
		{name: "One word", size: 32, expected: GasSHA3 + 1*GasSHA3Word},
		{name: "Two words", size: 64, expected: GasSHA3 + 2*GasSHA3Word},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateSHA3Gas(tt.size)
			if cost != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, cost)
			}
		})
	}
}

func TestCalculateLogGas(t *testing.T) {
	tests := []struct {
		name       string
		topicCount int
		dataSize   uint64
		expected   uint64
	}{
		{name: "LOG0 with data", topicCount: 0, dataSize: 100, expected: GasLog + 100*GasLogData},
		{name: "LOG2 with topics and data", topicCount: 2, dataSize: 50, expected: GasLog + 2*GasLogTopic + 50*GasLogData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateLogGas(tt.topicCount, tt.dataSize)
			if cost != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, cost)
			}
		})
	}
}

func TestDefaultGasTable(t *testing.T) {
	t.Run("DefaultGasTable returns valid table", func(t *testing.T) {
		gt := DefaultGasTable()
		if gt.SLoad != GasSLoad {
			t.Errorf("expected SLoad %d, got %d", GasSLoad, gt.SLoad)
		}
		if gt.Create != GasCreate {
			t.Errorf("expected Create %d, got %d", GasCreate, gt.Create)
		}
		if gt.CodeDeposit != GasCodeDeposit {
			t.Errorf("expected CodeDeposit %d, got %d", GasCodeDeposit, gt.CodeDeposit)
		}
	})
}

func TestCalculateCallGas(t *testing.T) {
	tests := []struct {
		name         string
		gasTable     *GasTable
		availableGas uint64
		requestedGas uint64
		hasValue     bool
		isNewAccount bool
		isCold       bool
	}{
		{name: "Simple call - cold", gasTable: DefaultGasTable(), availableGas: 10000, requestedGas: 5000, hasValue: false, isNewAccount: false, isCold: true},
		{name: "Call with value", gasTable: DefaultGasTable(), availableGas: 10000, requestedGas: 5000, hasValue: true, isNewAccount: false, isCold: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost, gasToSend := CalculateCallGas(tt.gasTable, tt.availableGas, tt.requestedGas, tt.hasValue, tt.isNewAccount, tt.isCold)
			if cost == 0 {
				t.Error("expected non-zero cost")
			}
			if gasToSend > tt.availableGas {
				t.Error("gas to send exceeds available")
			}
		})
	}
}
