// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

/**
 * Represents a blockchain block.
 */
public class Block {

    private final BigInteger number;
    private final Hash hash;
    private final Hash parentHash;
    private final BigInteger timestamp;
    private final List<Hash> transactions;
    private final BigInteger gasLimit;
    private final BigInteger gasUsed;
    private final Address miner;

    public Block(BigInteger number, Hash hash, Hash parentHash, BigInteger timestamp,
                 List<Hash> transactions, BigInteger gasLimit, BigInteger gasUsed, Address miner) {
        this.number = number;
        this.hash = hash;
        this.parentHash = parentHash;
        this.timestamp = timestamp;
        this.transactions = transactions != null ? List.copyOf(transactions) : Collections.emptyList();
        this.gasLimit = gasLimit;
        this.gasUsed = gasUsed;
        this.miner = miner;
    }

    public BigInteger getNumber() { return number; }
    public Hash getHash() { return hash; }
    public Hash getParentHash() { return parentHash; }
    public BigInteger getTimestamp() { return timestamp; }
    public List<Hash> getTransactions() { return transactions; }
    public BigInteger getGasLimit() { return gasLimit; }
    public BigInteger getGasUsed() { return gasUsed; }
    public Address getMiner() { return miner; }

    public boolean isGenesis() {
        return number.equals(BigInteger.ZERO);
    }

    public int getTransactionCount() {
        return transactions.size();
    }
}
