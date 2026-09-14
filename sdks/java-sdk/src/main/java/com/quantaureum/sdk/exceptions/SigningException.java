// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.exceptions;

/**
 * Exception for signing errors.
 *
 * <p>This exception is thrown when message or transaction signing fails.
 */
public class SigningException extends QuantaureumException {

    /**
     * Creates a new signing exception.
     *
     * @param message the error message
     */
    public SigningException(String message) {
        super(message);
    }

    /**
     * Creates a new signing exception with a cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
