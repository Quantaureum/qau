// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import com.quantaureum.sdk.utils.Hex;

import java.util.Arrays;

/**
 * Represents a 32-byte hash value.
 *
 * <p>This class is immutable and thread-safe.
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Create from hex string
 * Hash hash = Hash.fromHex("0x1234...");
 *
 * // Create from bytes
 * Hash hash = Hash.fromBytes(bytes);
 *
 * // Get hex representation
 * String hex = hash.toHex();
 * }</pre>
 */
public final class Hash {

    /** The zero hash (0x0000...0000) */
    public static final Hash ZERO = new Hash(new byte[32]);

    /** Hash length in bytes */
    public static final int LENGTH = 32;

    private final byte[] bytes;

    private Hash(byte[] bytes) {
        this.bytes = bytes.clone();
    }

    /**
     * Creates a Hash from a byte array.
     *
     * @param bytes the 32-byte hash
     * @return a Hash instance
     * @throws IllegalArgumentException if bytes is null or not 32 bytes
     */
    public static Hash fromBytes(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("Hash bytes cannot be null");
        }
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException(
                "Hash must be " + LENGTH + " bytes, got " + bytes.length);
        }
        return new Hash(bytes);
    }

    /**
     * Creates a Hash from a hex string.
     *
     * @param hex the hex-encoded hash (with or without 0x prefix)
     * @return a Hash instance
     * @throws IllegalArgumentException if hex is invalid
     */
    public static Hash fromHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            throw new IllegalArgumentException("Hash hex cannot be null or empty");
        }

        String cleanHex = hex.startsWith("0x") || hex.startsWith("0X")
            ? hex.substring(2) : hex;

        if (cleanHex.length() != LENGTH * 2) {
            throw new IllegalArgumentException(
                "Hash hex must be " + (LENGTH * 2) + " characters, got " + cleanHex.length());
        }

        byte[] bytes = Hex.toBytes(cleanHex);
        return new Hash(bytes);
    }

    /**
     * Returns the hash as a byte array.
     *
     * @return a copy of the hash bytes
     */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /**
     * Returns the hash as a lowercase hex string with 0x prefix.
     *
     * @return the hex-encoded hash
     */
    public String toHex() {
        return "0x" + Hex.toHexString(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Hash hash = (Hash) o;
        return Arrays.equals(bytes, hash.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toHex();
    }
}
