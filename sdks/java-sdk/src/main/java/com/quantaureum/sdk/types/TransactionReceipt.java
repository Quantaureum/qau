// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

/**
 * Represents a transaction receipt.
 */
public class TransactionReceipt {

    private final Hash transactionHash;
    private final Hash blockHash;
    private final BigInteger blockNumber;
    private final BigInteger transactionIndex;
    private final Address from;
    private final Address to;
    private final BigInteger gasUsed;
    private final BigInteger cumulativeGasUsed;
    private final Address contractAddress;
    private final List<Log> logs;
    private final BigInteger status;

    public TransactionReceipt(Hash transactionHash, Hash blockHash, BigInteger blockNumber,
                              BigInteger transactionIndex, Address from, Address to,
                              BigInteger gasUsed, BigInteger cumulativeGasUsed,
                              Address contractAddress, List<Log> logs, BigInteger status) {
        this.transactionHash = transactionHash;
        this.blockHash = blockHash;
        this.blockNumber = blockNumber;
        this.transactionIndex = transactionIndex;
        this.from = from;
        this.to = to;
        this.gasUsed = gasUsed;
        this.cumulativeGasUsed = cumulativeGasUsed;
        this.contractAddress = contractAddress;
        this.logs = logs != null ? List.copyOf(logs) : Collections.emptyList();
        this.status = status;
    }

    public Hash getTransactionHash() { return transactionHash; }
    public Hash getBlockHash() { return blockHash; }
    public BigInteger getBlockNumber() { return blockNumber; }
    public BigInteger getTransactionIndex() { return transactionIndex; }
    public Address getFrom() { return from; }
    public Address getTo() { return to; }
    public BigInteger getGasUsed() { return gasUsed; }
    public BigInteger getCumulativeGasUsed() { return cumulativeGasUsed; }
    public Address getContractAddress() { return contractAddress; }
    public List<Log> getLogs() { return logs; }
    public BigInteger getStatus() { return status; }

    public boolean isSuccess() {
        return status.equals(BigInteger.ONE);
    }
}
