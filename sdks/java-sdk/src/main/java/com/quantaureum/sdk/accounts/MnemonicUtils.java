// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.accounts;

import org.web3j.crypto.Bip32ECKeyPair;

import java.security.SecureRandom;

/**
 * Utility class for BIP-39 mnemonic operations.
 */
public final class MnemonicUtils {

    // BIP-44 path for Ethereum: m/44'/60'/0'/0/0
    private static final int[] BIP44_ETH_PATH = {
        44 | Bip32ECKeyPair.HARDENED_BIT,
        60 | Bip32ECKeyPair.HARDENED_BIT,
        0 | Bip32ECKeyPair.HARDENED_BIT,
        0,
        0
    };

    private MnemonicUtils() {
        // Utility class, no instantiation
    }

    /**
     * Generates a new mnemonic phrase.
     *
     * @param wordCount the number of words (12, 15, 18, 21, or 24)
     * @return the mnemonic phrase
     */
    public static String generateMnemonic(int wordCount) {
        int entropyBits;
        switch (wordCount) {
            case 12:
                entropyBits = 128;
                break;
            case 15:
                entropyBits = 160;
                break;
            case 18:
                entropyBits = 192;
                break;
            case 21:
                entropyBits = 224;
                break;
            case 24:
                entropyBits = 256;
                break;
            default:
                throw new IllegalArgumentException(
                    "Word count must be 12, 15, 18, 21, or 24, got " + wordCount);
        }

        byte[] entropy = new byte[entropyBits / 8];
        new SecureRandom().nextBytes(entropy);

        return org.web3j.crypto.MnemonicUtils.generateMnemonic(entropy);
    }

    /**
     * Validates a mnemonic phrase.
     *
     * @param mnemonic the mnemonic to validate
     * @return true if valid
     */
    public static boolean isValidMnemonic(String mnemonic) {
        if (mnemonic == null || mnemonic.trim().isEmpty()) {
            return false;
        }

        try {
            org.web3j.crypto.MnemonicUtils.validateMnemonic(mnemonic);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Derives a private key from a mnemonic phrase using default Ethereum path.
     *
     * @param mnemonic the mnemonic phrase
     * @return the 32-byte private key
     */
    public static byte[] derivePrivateKey(String mnemonic) {
        return derivePrivateKey(mnemonic, 0);
    }

    /**
     * Derives a private key from a mnemonic phrase.
     *
     * @param mnemonic the mnemonic phrase
     * @param accountIndex the account index (0-based)
     * @return the 32-byte private key
     */
    public static byte[] derivePrivateKey(String mnemonic, int accountIndex) {
        if (mnemonic == null || mnemonic.trim().isEmpty()) {
            throw new IllegalArgumentException("Mnemonic cannot be null or empty");
        }

        if (!isValidMnemonic(mnemonic)) {
            throw new IllegalArgumentException("Invalid mnemonic phrase");
        }

        // Calculate seed from mnemonic
        byte[] seed = org.web3j.crypto.MnemonicUtils.generateSeed(mnemonic, "");

        // Create master key pair
        Bip32ECKeyPair masterKeyPair = Bip32ECKeyPair.generateKeyPair(seed);

        // Derive using BIP-44 path with account index
        int[] path = {
            44 | Bip32ECKeyPair.HARDENED_BIT,
            60 | Bip32ECKeyPair.HARDENED_BIT,
            accountIndex | Bip32ECKeyPair.HARDENED_BIT,
            0,
            0
        };

        Bip32ECKeyPair derivedKeyPair = Bip32ECKeyPair.deriveKeyPair(masterKeyPair, path);

        return derivedKeyPair.getPrivateKey().toByteArray();
    }

    /**
     * Derives a private key from a mnemonic phrase with a custom derivation path.
     *
     * @param mnemonic the mnemonic phrase
     * @param path the derivation path (e.g., "m/44'/60'/0'/0/0")
     * @return the 32-byte private key
     */
    public static byte[] derivePrivateKey(String mnemonic, String path) {
        if (mnemonic == null || mnemonic.trim().isEmpty()) {
            throw new IllegalArgumentException("Mnemonic cannot be null or empty");
        }

        if (!isValidMnemonic(mnemonic)) {
            throw new IllegalArgumentException("Invalid mnemonic phrase");
        }

        // Calculate seed from mnemonic
        byte[] seed = org.web3j.crypto.MnemonicUtils.generateSeed(mnemonic, "");

        // Create master key pair
        Bip32ECKeyPair masterKeyPair = Bip32ECKeyPair.generateKeyPair(seed);

        // Parse path and derive
        int[] pathArray = parsePath(path);
        Bip32ECKeyPair derivedKeyPair = Bip32ECKeyPair.deriveKeyPair(masterKeyPair, pathArray);

        byte[] privateKeyBytes = derivedKeyPair.getPrivateKey().toByteArray();

        // Ensure 32 bytes (BigInteger may add leading zero or be shorter)
        if (privateKeyBytes.length == 32) {
            return privateKeyBytes;
        } else if (privateKeyBytes.length > 32) {
            byte[] result = new byte[32];
            System.arraycopy(privateKeyBytes, privateKeyBytes.length - 32, result, 0, 32);
            return result;
        } else {
            byte[] result = new byte[32];
            System.arraycopy(privateKeyBytes, 0, result, 32 - privateKeyBytes.length, privateKeyBytes.length);
            return result;
        }
    }

    /**
     * Parses a BIP-44 derivation path string.
     *
     * @param path the path string (e.g., "m/44'/60'/0'/0/0")
     * @return the path as an int array
     */
    private static int[] parsePath(String path) {
        String[] parts = path.split("/");
        java.util.List<Integer> indices = new java.util.ArrayList<>();

        for (String part : parts) {
            if (part.equals("m") || part.isEmpty()) {
                continue;
            }

            boolean hardened = part.endsWith("'") || part.endsWith("H");
            String indexStr = hardened ? part.substring(0, part.length() - 1) : part;
            int index = Integer.parseInt(indexStr);

            if (hardened) {
                index |= Bip32ECKeyPair.HARDENED_BIT;
            }

            indices.add(index);
        }

        return indices.stream().mapToInt(Integer::intValue).toArray();
    }
}
