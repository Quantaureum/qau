// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.exceptions;

import java.util.Optional;

/**
 * Exception for RPC communication errors.
 *
 * <p>This exception is thrown when an RPC call fails, either due to
 * network issues or an error response from the node.
 */
public class RpcException extends QuantaureumException {

    private final int code;
    private final String rpcMessage;
    private final String data;

    /**
     * Creates a new RPC exception.
     *
     * @param code the RPC error code
     * @param message the error message
     * @param data optional additional data
     */
    public RpcException(int code, String message, String data) {
        super(formatMessage(code, message));
        this.code = code;
        this.rpcMessage = message;
        this.data = data;
    }

    /**
     * Creates a new RPC exception for connection errors.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public RpcException(String message, Throwable cause) {
        super(message, cause);
        this.code = -1;
        this.rpcMessage = message;
        this.data = null;
    }

    private static String formatMessage(int code, String message) {
        return String.format("RPC error %d: %s", code, message);
    }

    /**
     * Gets the RPC error code.
     *
     * @return the error code, or -1 for connection errors
     */
    public int getCode() {
        return code;
    }

    /**
     * Gets the RPC error message.
     *
     * @return the error message
     */
    public String getRpcMessage() {
        return rpcMessage;
    }

    /**
     * Gets the optional additional data.
     *
     * @return the data if present
     */
    public Optional<String> getData() {
        return Optional.ofNullable(data);
    }

    /**
     * Checks if this is a connection error.
     *
     * @return true if this is a connection error
     */
    public boolean isConnectionError() {
        return code == -1 || code == -32603;
    }

    /**
     * Checks if this is a revert error.
     *
     * @return true if the transaction reverted
     */
    public boolean isRevert() {
        return code == 3 || (data != null && data.startsWith("0x08c379a0"));
    }

    /**
     * Extracts the revert reason if available.
     *
     * @return the revert reason if present
     */
    public Optional<String> getRevertReason() {
        if (data == null) {
            return Optional.empty();
        }

        // Check for Error(string) selector: 0x08c379a0
        if (data.startsWith("0x08c379a0") && data.length() > 138) {
            try {
                // Skip selector (4 bytes) + offset (32 bytes) + length position
                String hexLength = data.substring(74, 138);
                int length = Integer.parseInt(hexLength, 16);
                if (length > 0 && data.length() >= 138 + length * 2) {
                    String hexString = data.substring(138, 138 + length * 2);
                    byte[] bytes = hexToBytes(hexString);
                    return Optional.of(new String(bytes));
                }
            } catch (Exception e) {
                // Fall through to return empty
            }
        }

        return Optional.empty();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
