// Quantaureum Node source, version 1.0.0.
// Test: the simplest possible QVM contract
// Behavior: returns the 32-byte value 0x01
// QVM opcodes: PUSH1=0x10, MSTORE8=0x52, PUSH1=0x10, PUSH1=0x10, RETURN=0x06

    PUSH1 0x01        // push the value 1
    PUSH1 0x00        // offset 0
    MSTORE8           // store byte 0x01 at memory offset 0
    PUSH1 0x20        // return length 32
    PUSH1 0x00        // return offset 0
    RETURN            // return memory[0:32]
