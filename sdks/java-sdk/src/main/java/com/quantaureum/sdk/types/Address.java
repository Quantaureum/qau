// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import com.quantaureum.sdk.utils.Hex;
import com.quantaureum.sdk.utils.Keccak256;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a 20-byte blockchain address.
 *
 * <p>This class is immutable and thread-safe.
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Create from hex string
 * Address addr = Address.fromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00");
 *
 * // Create from bytes
 * Address addr = Address.fromBytes(bytes);
 *
 * // Get checksum address
 * String checksum = addr.toChecksumHex();
 * }</pre>
 */
public final class Address {

    /** The zero address (0x0000...0000) */
    public static final Address ZERO = new Address(new byte[20]);

    /** Address length in bytes */
    public static final int LENGTH = 20;

    private final byte[] bytes;

    private Address(byte[] bytes) {
        this.bytes = bytes.clone();
    }

    /**
     * Creates an Address from a byte array.
     *
     * @param bytes the 20-byte address
     * @return an Address instance
     * @throws IllegalArgumentException if bytes is null or not 20 bytes
     */
    public static Address fromBytes(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("Address bytes cannot be null");
        }
        if (bytes.length != LENGTH) {
            throw new IllegalArgumentException(
                "Address must be " + LENGTH + " bytes, got " + bytes.length);
        }
        return new Address(bytes);
    }

    /**
     * Creates an Address from a hex string.
     *
     * @param hex the hex-encoded address (with or without 0x prefix)
     * @return an Address instance
     * @throws IllegalArgumentException if hex is invalid
     */
    public static Address fromHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            throw new IllegalArgumentException("Address hex cannot be null or empty");
        }

        String cleanHex = hex.startsWith("0x") || hex.startsWith("0X")
            ? hex.substring(2) : hex;

        if (cleanHex.length() != LENGTH * 2) {
            throw new IllegalArgumentException(
                "Address hex must be " + (LENGTH * 2) + " characters, got " + cleanHex.length());
        }

        byte[] bytes = Hex.toBytes(cleanHex);
        return new Address(bytes);
    }

    /**
     * Validates if a string is a valid address format.
     *
     * @param address the address string to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }

        String cleanHex = address.startsWith("0x") || address.startsWith("0X")
            ? address.substring(2) : address;

        if (cleanHex.length() != LENGTH * 2) {
            return false;
        }

        for (char c : cleanHex.toCharArray()) {
            if (!isHexChar(c)) {
                return false;
            }
        }

        return true;
    }

    private static boolean isHexChar(char c) {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }

    /**
     * Returns the address as a byte array.
     *
     * @return a copy of the address bytes
     */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /**
     * Returns the address as a lowercase hex string with 0x prefix.
     *
     * @return the hex-encoded address
     */
    public String toHex() {
        return "0x" + Hex.toHexString(bytes);
    }

    /**
     * Returns the address in EIP-55 checksum format.
     *
     * @return the checksum-encoded address
     */
    public String toChecksumHex() {
        String hex = Hex.toHexString(bytes).toLowerCase();
        byte[] hashBytes = Keccak256.hash(hex.getBytes());
        String hash = Hex.toHexString(hashBytes);

        StringBuilder result = new StringBuilder("0x");
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (c >= 'a' && c <= 'f') {
                // Check if corresponding hash nibble is >= 8
                int hashNibble = Character.digit(hash.charAt(i), 16);
                if (hashNibble >= 8) {
                    result.append(Character.toUpperCase(c));
                } else {
                    result.append(c);
                }
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Address address = (Address) o;
        return Arrays.equals(bytes, address.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return toChecksumHex();
    }
}
