// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

/**
 * Represents a log entry from a transaction receipt.
 */
public class Log {

    private final Address address;
    private final List<Hash> topics;
    private final byte[] data;
    private final BigInteger blockNumber;
    private final Hash transactionHash;
    private final BigInteger transactionIndex;
    private final Hash blockHash;
    private final BigInteger logIndex;

    public Log(Address address, List<Hash> topics, byte[] data, BigInteger blockNumber,
               Hash transactionHash, BigInteger transactionIndex, Hash blockHash, BigInteger logIndex) {
        this.address = address;
        this.topics = topics != null ? List.copyOf(topics) : Collections.emptyList();
        this.data = data != null ? data.clone() : new byte[0];
        this.blockNumber = blockNumber;
        this.transactionHash = transactionHash;
        this.transactionIndex = transactionIndex;
        this.blockHash = blockHash;
        this.logIndex = logIndex;
    }

    public Address getAddress() { return address; }
    public List<Hash> getTopics() { return topics; }
    public byte[] getData() { return data.clone(); }
    public BigInteger getBlockNumber() { return blockNumber; }
    public Hash getTransactionHash() { return transactionHash; }
    public BigInteger getTransactionIndex() { return transactionIndex; }
    public Hash getBlockHash() { return blockHash; }
    public BigInteger getLogIndex() { return logIndex; }
}
