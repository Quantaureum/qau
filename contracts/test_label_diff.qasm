// Quantaureum Node source, version 1.0.0.
// Test label difference expressions
// Constructor pattern: CODECOPY+RETURN the runtime code

.INIT
    // return the runtime code
    PUSH2 @code_end-@code_start   // size = code_end - code_start
    PUSH2 @code_start             // offset = code_start
    PUSH1 0x00                    // destOffset = 0
    CODECOPY
    PUSH2 @code_end-@code_start   // size
    PUSH1 0x00                    // offset
    RETURN

.CODE
code_start:
    PUSH1 0x42
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN
code_end:
