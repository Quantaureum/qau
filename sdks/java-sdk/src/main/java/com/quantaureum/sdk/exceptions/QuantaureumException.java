// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.exceptions;

/**
 * Base exception for all Quantaureum SDK errors.
 *
 * <p>This is the parent class for all SDK-specific exceptions.
 * It extends RuntimeException to avoid forcing checked exception handling.
 */
public class QuantaureumException extends RuntimeException {

    /**
     * Creates a new exception with the specified message.
     *
     * @param message the error message
     */
    public QuantaureumException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public QuantaureumException(String message, Throwable cause) {
        super(message, cause);
    }
}
