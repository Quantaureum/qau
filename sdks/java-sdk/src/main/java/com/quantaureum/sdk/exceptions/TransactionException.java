// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.exceptions;

import com.quantaureum.sdk.types.Hash;

import java.util.Optional;

/**
 * Exception for transaction errors.
 *
 * <p>This exception is thrown when a transaction fails, either during
 * submission or execution.
 */
public class TransactionException extends QuantaureumException {

    private final Hash transactionHash;
    private final String revertReason;

    /**
     * Creates a new transaction exception with just a message.
     *
     * @param message the error message
     */
    public TransactionException(String message) {
        super(message);
        this.transactionHash = null;
        this.revertReason = message;
    }

    /**
     * Creates a new transaction exception with a message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public TransactionException(String message, Throwable cause) {
        super(message, cause);
        this.transactionHash = null;
        this.revertReason = message;
    }

    /**
     * Creates a new transaction exception.
     *
     * @param hash the transaction hash (may be null)
     * @param reason the failure reason
     */
    public TransactionException(Hash hash, String reason) {
        super(formatMessage(hash, reason));
        this.transactionHash = hash;
        this.revertReason = reason;
    }

    /**
     * Creates a new transaction exception with a cause.
     *
     * @param hash the transaction hash (may be null)
     * @param reason the failure reason
     * @param cause the underlying cause
     */
    public TransactionException(Hash hash, String reason, Throwable cause) {
        super(formatMessage(hash, reason), cause);
        this.transactionHash = hash;
        this.revertReason = reason;
    }

    private static String formatMessage(Hash hash, String reason) {
        if (hash != null) {
            return String.format("Transaction %s failed: %s", hash.toHex(), reason);
        }
        return String.format("Transaction failed: %s", reason);
    }

    /**
     * Gets the transaction hash if available.
     *
     * @return the transaction hash
     */
    public Optional<Hash> getTransactionHash() {
        return Optional.ofNullable(transactionHash);
    }

    /**
     * Gets the revert reason if available.
     *
     * @return the revert reason
     */
    public Optional<String> getRevertReason() {
        return Optional.ofNullable(revertReason);
    }
}
