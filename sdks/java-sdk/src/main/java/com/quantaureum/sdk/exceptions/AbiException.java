// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.exceptions;

/**
 * Exception for ABI encoding/decoding errors.
 *
 * <p>This exception is thrown when ABI encoding or decoding fails.
 */
public class AbiException extends QuantaureumException {

    /**
     * Creates a new ABI exception.
     *
     * @param message the error message
     */
    public AbiException(String message) {
        super(message);
    }

    /**
     * Creates a new ABI exception with a cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public AbiException(String message, Throwable cause) {
        super(message, cause);
    }
}
