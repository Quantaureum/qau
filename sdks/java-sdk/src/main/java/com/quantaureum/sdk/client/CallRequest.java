// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.client;

import com.quantaureum.sdk.types.Address;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Represents a call request for read-only contract calls.
 */
public class CallRequest {

    private final Address from;
    private final Address to;
    private final BigInteger gas;
    private final BigInteger gasPrice;
    private final BigInteger value;
    private final byte[] data;

    private CallRequest(Builder builder) {
        this.from = builder.from;
        this.to = builder.to;
        this.gas = builder.gas;
        this.gasPrice = builder.gasPrice;
        this.value = builder.value;
        this.data = builder.data;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Optional<Address> getFrom() { return Optional.ofNullable(from); }
    public Address getTo() { return to; }
    public Optional<BigInteger> getGas() { return Optional.ofNullable(gas); }
    public Optional<BigInteger> getGasPrice() { return Optional.ofNullable(gasPrice); }
    public Optional<BigInteger> getValue() { return Optional.ofNullable(value); }
    public Optional<byte[]> getData() { return Optional.ofNullable(data != null ? data.clone() : null); }

    public static class Builder {
        private Address from;
        private Address to;
        private BigInteger gas;
        private BigInteger gasPrice;
        private BigInteger value;
        private byte[] data;

        public Builder from(Address from) { this.from = from; return this; }
        public Builder from(String from) { this.from = from != null ? Address.fromHex(from) : null; return this; }
        public Builder to(Address to) { this.to = to; return this; }
        public Builder to(String to) { this.to = to != null ? Address.fromHex(to) : null; return this; }
        public Builder gas(BigInteger gas) { this.gas = gas; return this; }
        public Builder gasPrice(BigInteger gasPrice) { this.gasPrice = gasPrice; return this; }
        public Builder value(BigInteger value) { this.value = value; return this; }
        public Builder data(byte[] data) { this.data = data != null ? data.clone() : null; return this; }
        public Builder data(String hexData) {
            if (hexData != null) {
                String clean = hexData.startsWith("0x") ? hexData.substring(2) : hexData;
                this.data = new byte[clean.length() / 2];
                for (int i = 0; i < this.data.length; i++) {
                    this.data[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
                }
            }
            return this;
        }

        public CallRequest build() {
            if (to == null) {
                throw new IllegalArgumentException("To address is required");
            }
            return new CallRequest(this);
        }
    }
}
