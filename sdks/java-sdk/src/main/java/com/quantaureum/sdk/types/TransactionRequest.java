// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Represents a transaction request.
 */
public class TransactionRequest {

    private final Address from;
    private final Address to;
    private final BigInteger gas;
    private final BigInteger gasPrice;
    private final BigInteger value;
    private final byte[] data;
    private final BigInteger nonce;

    private TransactionRequest(Builder builder) {
        this.from = builder.from;
        this.to = builder.to;
        this.gas = builder.gas;
        this.gasPrice = builder.gasPrice;
        this.value = builder.value;
        this.data = builder.data;
        this.nonce = builder.nonce;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Optional<Address> getFrom() { return Optional.ofNullable(from); }
    public Optional<Address> getTo() { return Optional.ofNullable(to); }
    public Optional<BigInteger> getGas() { return Optional.ofNullable(gas); }
    public Optional<BigInteger> getGasPrice() { return Optional.ofNullable(gasPrice); }
    public Optional<BigInteger> getValue() { return Optional.ofNullable(value); }
    public Optional<byte[]> getData() { return Optional.ofNullable(data != null ? data.clone() : null); }
    public Optional<BigInteger> getNonce() { return Optional.ofNullable(nonce); }

    public static class Builder {
        private Address from;
        private Address to;
        private BigInteger gas;
        private BigInteger gasPrice;
        private BigInteger value;
        private byte[] data;
        private BigInteger nonce;

        public Builder from(Address from) { this.from = from; return this; }
        public Builder to(Address to) { this.to = to; return this; }
        public Builder gas(BigInteger gas) { this.gas = gas; return this; }
        public Builder gas(long gas) { this.gas = BigInteger.valueOf(gas); return this; }
        public Builder gasLimit(BigInteger gasLimit) { this.gas = gasLimit; return this; }
        public Builder gasLimit(long gasLimit) { this.gas = BigInteger.valueOf(gasLimit); return this; }
        public Builder gasPrice(BigInteger gasPrice) { this.gasPrice = gasPrice; return this; }
        public Builder value(BigInteger value) { this.value = value; return this; }
        public Builder data(byte[] data) { this.data = data != null ? data.clone() : null; return this; }
        public Builder nonce(BigInteger nonce) { this.nonce = nonce; return this; }
        public Builder nonce(long nonce) { this.nonce = BigInteger.valueOf(nonce); return this; }

        public TransactionRequest build() {
            return new TransactionRequest(this);
        }
    }
}
