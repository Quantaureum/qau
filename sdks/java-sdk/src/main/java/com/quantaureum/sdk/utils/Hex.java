// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.utils;

/**
 * Utility class for hexadecimal conversions.
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Convert bytes to hex
 * String hex = Hex.toHexString(bytes);
 *
 * // Convert hex to bytes
 * byte[] bytes = Hex.toBytes("0x1234");
 *
 * // Check for 0x prefix
 * boolean hasPrefix = Hex.has0xPrefix("0x1234");
 * }</pre>
 */
public final class Hex {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private Hex() {
        // Utility class, no instantiation
    }

    /**
     * Converts a byte array to a lowercase hex string without 0x prefix.
     *
     * @param bytes the bytes to convert
     * @return the hex string
     * @throws IllegalArgumentException if bytes is null
     */
    public static String toHexString(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("Bytes cannot be null");
        }

        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[v >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Converts a hex string to a byte array.
     *
     * @param hex the hex string (with or without 0x prefix)
     * @return the byte array
     * @throws IllegalArgumentException if hex is invalid
     */
    public static byte[] toBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("Hex string cannot be null");
        }

        String cleanHex = hex.startsWith("0x") || hex.startsWith("0X")
            ? hex.substring(2) : hex;

        if (cleanHex.isEmpty()) {
            return new byte[0];
        }

        if (cleanHex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] bytes = new byte[cleanHex.length() / 2];
        for (int i = 0; i < cleanHex.length(); i += 2) {
            int high = hexCharToInt(cleanHex.charAt(i));
            int low = hexCharToInt(cleanHex.charAt(i + 1));
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException(
                    "Invalid hex character at position " + i);
            }
            bytes[i / 2] = (byte) ((high << 4) | low);
        }
        return bytes;
    }

    /**
     * Checks if a string has the 0x prefix.
     *
     * @param hex the string to check
     * @return true if it has the 0x prefix
     */
    public static boolean has0xPrefix(String hex) {
        return hex != null && (hex.startsWith("0x") || hex.startsWith("0X"));
    }

    /**
     * Adds the 0x prefix if not present.
     *
     * @param hex the hex string
     * @return the hex string with 0x prefix
     */
    public static String add0xPrefix(String hex) {
        if (hex == null) {
            return "0x";
        }
        return has0xPrefix(hex) ? hex : "0x" + hex;
    }

    /**
     * Removes the 0x prefix if present.
     *
     * @param hex the hex string
     * @return the hex string without 0x prefix
     */
    public static String remove0xPrefix(String hex) {
        if (hex == null) {
            return "";
        }
        return has0xPrefix(hex) ? hex.substring(2) : hex;
    }

    /**
     * Validates if a string is valid hex.
     *
     * @param hex the string to validate
     * @return true if valid hex
     */
    public static boolean isValidHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return false;
        }

        String cleanHex = remove0xPrefix(hex);
        if (cleanHex.isEmpty()) {
            return true; // "0x" is valid
        }

        for (char c : cleanHex.toCharArray()) {
            if (hexCharToInt(c) == -1) {
                return false;
            }
        }
        return true;
    }

    private static int hexCharToInt(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }
}
