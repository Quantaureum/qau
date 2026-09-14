// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.contracts;

import com.quantaureum.sdk.client.QuantaureumClient;
import com.quantaureum.sdk.exceptions.RpcException;
import com.quantaureum.sdk.exceptions.TransactionException;
import com.quantaureum.sdk.types.Hash;
import com.quantaureum.sdk.types.TransactionReceipt;

import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Represents a pending transaction that can be awaited for confirmation.
 */
public class PendingTransaction {
    private final QuantaureumClient client;
    private final Hash txHash;

    private static final long DEFAULT_TIMEOUT_MS = 120_000; // 2 minutes
    private static final long POLL_INTERVAL_MS = 1_000; // 1 second

    /**
     * Create a pending transaction.
     *
     * @param client The Quantaureum client
     * @param txHash The transaction hash
     */
    public PendingTransaction(QuantaureumClient client, Hash txHash) {
        this.client = client;
        this.txHash = txHash;
    }

    /**
     * Get the transaction hash.
     */
    public Hash getHash() {
        return txHash;
    }

    /**
     * Wait for the transaction to be mined with default timeout.
     *
     * @return The transaction receipt
     * @throws TransactionException if the transaction fails or times out
     */
    public TransactionReceipt await() throws TransactionException, RpcException {
        return await(DEFAULT_TIMEOUT_MS);
    }

    /**
     * Wait for the transaction to be mined with custom timeout.
     *
     * @param timeoutMs Timeout in milliseconds
     * @return The transaction receipt
     * @throws TransactionException if the transaction fails or times out
     */
    public TransactionReceipt await(long timeoutMs) throws TransactionException, RpcException {
        long startTime = System.currentTimeMillis();

        while (System.currentTimeMillis() - startTime < timeoutMs) {
            Optional<TransactionReceipt> receiptOpt = client.getTransactionReceipt(txHash);

            if (receiptOpt.isPresent()) {
                TransactionReceipt receipt = receiptOpt.get();
                // Check if transaction succeeded (status 0 means reverted)
                if (receipt.getStatus() != null && receipt.getStatus().equals(BigInteger.ZERO)) {
                    throw new TransactionException(txHash, "Transaction reverted");
                }
                return receipt;
            }

            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TransactionException("Transaction wait interrupted", e);
            }
        }

        throw new TransactionException(txHash, "Transaction timeout after " + timeoutMs + "ms");
    }

    /**
     * Wait for the transaction to be mined with specified number of confirmations.
     *
     * @param confirmations Number of block confirmations to wait for
     * @return The transaction receipt
     * @throws TransactionException if the transaction fails or times out
     */
    public TransactionReceipt await(int confirmations) throws TransactionException, RpcException {
        return await(confirmations, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Wait for the transaction with confirmations and custom timeout.
     *
     * @param confirmations Number of block confirmations to wait for
     * @param timeoutMs     Timeout in milliseconds
     * @return The transaction receipt
     * @throws TransactionException if the transaction fails or times out
     */
    public TransactionReceipt await(int confirmations, long timeoutMs) throws TransactionException, RpcException {
        // First wait for the transaction to be mined
        TransactionReceipt receipt = await(timeoutMs);

        if (confirmations <= 1) {
            return receipt;
        }

        // Wait for additional confirmations
        long startTime = System.currentTimeMillis();

        while (System.currentTimeMillis() - startTime < timeoutMs) {
            BigInteger currentBlock = client.getBlockNumber();
            BigInteger txBlock = receipt.getBlockNumber();
            BigInteger currentConfirmations = currentBlock.subtract(txBlock).add(BigInteger.ONE);

            if (currentConfirmations.compareTo(BigInteger.valueOf(confirmations)) >= 0) {
                return receipt;
            }

            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new TransactionException("Confirmation wait interrupted", e);
            }
        }

        throw new TransactionException(txHash, "Timeout waiting for " + confirmations + " confirmations");
    }

    /**
     * Wait for the transaction asynchronously.
     *
     * @return A CompletableFuture that resolves to the transaction receipt
     */
    public CompletableFuture<TransactionReceipt> awaitAsync() {
        return awaitAsync(DEFAULT_TIMEOUT_MS);
    }

    /**
     * Wait for the transaction asynchronously with custom timeout.
     *
     * @param timeoutMs Timeout in milliseconds
     * @return A CompletableFuture that resolves to the transaction receipt
     */
    public CompletableFuture<TransactionReceipt> awaitAsync(long timeoutMs) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return await(timeoutMs);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Wait for the transaction asynchronously with confirmations.
     *
     * @param confirmations Number of block confirmations to wait for
     * @return A CompletableFuture that resolves to the transaction receipt
     */
    public CompletableFuture<TransactionReceipt> awaitAsync(int confirmations) {
        return awaitAsync(confirmations, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Wait for the transaction asynchronously with confirmations and timeout.
     *
     * @param confirmations Number of block confirmations to wait for
     * @param timeoutMs     Timeout in milliseconds
     * @return A CompletableFuture that resolves to the transaction receipt
     */
    public CompletableFuture<TransactionReceipt> awaitAsync(int confirmations, long timeoutMs) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return await(confirmations, timeoutMs);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public String toString() {
        return "PendingTransaction{hash=" + txHash.toHex() + "}";
    }
}
