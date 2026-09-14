// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.client;

import java.time.Duration;

/**
 * Configuration for QuantaureumClient.
 */
public class ClientConfig {

    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final Duration writeTimeout;
    private final int maxRetries;

    private ClientConfig(Builder builder) {
        this.connectTimeout = builder.connectTimeout;
        this.readTimeout = builder.readTimeout;
        this.writeTimeout = builder.writeTimeout;
        this.maxRetries = builder.maxRetries;
    }

    public static ClientConfig defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public Duration getConnectTimeout() { return connectTimeout; }
    public Duration getReadTimeout() { return readTimeout; }
    public Duration getWriteTimeout() { return writeTimeout; }
    public int getMaxRetries() { return maxRetries; }

    public static class Builder {
        private Duration connectTimeout = Duration.ofSeconds(10);
        private Duration readTimeout = Duration.ofSeconds(30);
        private Duration writeTimeout = Duration.ofSeconds(30);
        private int maxRetries = 3;

        public Builder connectTimeout(Duration timeout) { this.connectTimeout = timeout; return this; }
        public Builder readTimeout(Duration timeout) { this.readTimeout = timeout; return this; }
        public Builder writeTimeout(Duration timeout) { this.writeTimeout = timeout; return this; }
        public Builder maxRetries(int retries) { this.maxRetries = retries; return this; }

        public ClientConfig build() {
            return new ClientConfig(this);
        }
    }
}
