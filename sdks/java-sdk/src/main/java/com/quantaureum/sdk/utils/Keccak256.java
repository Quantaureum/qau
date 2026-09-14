// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.utils;

import com.quantaureum.sdk.types.Hash;
import org.bouncycastle.jcajce.provider.digest.Keccak;

/**
 * Utility class for Keccak-256 hashing.
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Hash bytes
 * byte[] hash = Keccak256.hash(data);
 *
 * // Hash string
 * byte[] hash = Keccak256.hash("hello".getBytes());
 *
 * // Get Hash object
 * Hash hash = Keccak256.hashToHash(data);
 * }</pre>
 */
public final class Keccak256 {

    private Keccak256() {
        // Utility class, no instantiation
    }

    /**
     * Computes the Keccak-256 hash of the input data.
     *
     * @param data the data to hash
     * @return the 32-byte hash
     * @throws IllegalArgumentException if data is null
     */
    public static byte[] hash(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        Keccak.Digest256 digest = new Keccak.Digest256();
        return digest.digest(data);
    }

    /**
     * Computes the Keccak-256 hash and returns it as a Hash object.
     *
     * @param data the data to hash
     * @return the Hash object
     * @throws IllegalArgumentException if data is null
     */
    public static Hash hashToHash(byte[] data) {
        return Hash.fromBytes(hash(data));
    }

    /**
     * Computes the Keccak-256 hash and returns it as a hex string.
     *
     * @param data the data to hash
     * @return the hex-encoded hash with 0x prefix
     * @throws IllegalArgumentException if data is null
     */
    public static String hashToHex(byte[] data) {
        return "0x" + Hex.toHexString(hash(data));
    }
}
