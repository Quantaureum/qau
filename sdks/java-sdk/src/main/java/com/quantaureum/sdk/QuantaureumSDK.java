// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk;

import com.quantaureum.sdk.accounts.Account;
import com.quantaureum.sdk.client.QuantaureumClient;
import com.quantaureum.sdk.client.ClientConfig;

/**
 * Main entry point for the Quantaureum Java SDK.
 *
 * <p>This class provides convenient factory methods for creating SDK components.
 *
 * <h2>Quick Start</h2>
 * <pre>{@code
 * // Create a client
 * QuantaureumClient client = QuantaureumSDK.createClient("http://localhost:8545");
 *
 * // Create a new account
 * Account account = QuantaureumSDK.createAccount();
 *
 * // Get balance
 * BigInteger balance = client.getBalance(account.getAddress());
 * }</pre>
 *
 * @author Quantaureum Team
 * @version 0.1.0
 */
public final class QuantaureumSDK {

    /** SDK version */
    public static final String VERSION = "0.1.0";

    private QuantaureumSDK() {
        // Utility class, no instantiation
    }

    /**
     * Creates a new client connected to the specified URL.
     *
     * @param url the RPC endpoint URL
     * @return a new QuantaureumClient instance
     */
    public static QuantaureumClient createClient(String url) {
        return new QuantaureumClient(url);
    }

    /**
     * Creates a new client with custom configuration.
     *
     * @param url the RPC endpoint URL
     * @param config the client configuration
     * @return a new QuantaureumClient instance
     */
    public static QuantaureumClient createClient(String url, ClientConfig config) {
        return new QuantaureumClient(url, config);
    }

    /**
     * Creates a new random account.
     *
     * @return a new Account with a randomly generated private key
     */
    public static Account createAccount() {
        return Account.create();
    }

    /**
     * Creates an account from a private key.
     *
     * @param privateKey the private key bytes (32 bytes)
     * @return an Account instance
     */
    public static Account accountFromPrivateKey(byte[] privateKey) {
        return Account.fromPrivateKey(privateKey);
    }

    /**
     * Creates an account from a hex-encoded private key.
     *
     * @param hex the hex-encoded private key (with or without 0x prefix)
     * @return an Account instance
     */
    public static Account accountFromPrivateKeyHex(String hex) {
        return Account.fromPrivateKeyHex(hex);
    }

    /**
     * Creates an account from a mnemonic phrase.
     *
     * @param mnemonic the BIP-39 mnemonic phrase
     * @return an Account instance
     */
    public static Account accountFromMnemonic(String mnemonic) {
        return Account.fromMnemonic(mnemonic);
    }

    /**
     * Generates a new 12-word mnemonic phrase.
     *
     * @return a new BIP-39 mnemonic phrase
     */
    public static String generateMnemonic() {
        return Account.generateMnemonic();
    }
}
