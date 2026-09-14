// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.accounts;

import com.quantaureum.sdk.exceptions.SigningException;
import com.quantaureum.sdk.types.Address;
import com.quantaureum.sdk.types.Hash;
import com.quantaureum.sdk.types.SignedTransaction;
import com.quantaureum.sdk.types.TransactionRequest;
import com.quantaureum.sdk.utils.Hex;
import com.quantaureum.sdk.utils.Keccak256;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

// audit-fix JAVA-CRIT-2: Import Dilithium3 post-quantum signature support.
// The old code used only ECDSA (secp256k1) for all signing operations, which
// is vulnerable to quantum computer attacks via Shor's algorithm. Quantaureum
// requires Dilithium3 for quantum-resistant signatures. ECDSA is retained as
// a fallback for legacy/compatibility mode only.
import com.quantaureum.sdk.crypto.Dilithium3;
import com.quantaureum.sdk.crypto.Dilithium3Signature;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

/**
 * Represents a blockchain account with signing capabilities.
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Create a new random account
 * Account account = Account.create();
 *
 * // Create from private key
 * Account account = Account.fromPrivateKeyHex("0x...");
 *
 * // Create from mnemonic
 * Account account = Account.fromMnemonic("word1 word2 ...");
 *
 * // Sign a message
 * Signature sig = account.signMessage("Hello".getBytes());
 * }</pre>
 */
public class Account {

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
        CURVE_PARAMS.getCurve(),
        CURVE_PARAMS.getG(),
        CURVE_PARAMS.getN(),
        CURVE_PARAMS.getH()
    );
    private static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

    private final byte[] privateKey;
    private final Address address;
    private final String mnemonic;

    private Account(byte[] privateKey, String mnemonic) {
        this.privateKey = privateKey.clone();
        this.address = deriveAddress(privateKey);
        this.mnemonic = mnemonic;
    }

    /**
     * Creates a new random account.
     *
     * @return a new Account with a randomly generated private key
     */
    public static Account create() {
        return create(new SecureRandom());
    }

    /**
     * Creates a new random account with the specified SecureRandom.
     *
     * @param random the random number generator
     * @return a new Account
     */
    public static Account create(SecureRandom random) {
        byte[] privateKey = new byte[32];
        random.nextBytes(privateKey);

        // Ensure the key is valid (non-zero and less than curve order)
        BigInteger keyInt = new BigInteger(1, privateKey);
        while (keyInt.equals(BigInteger.ZERO) || keyInt.compareTo(CURVE.getN()) >= 0) {
            random.nextBytes(privateKey);
            keyInt = new BigInteger(1, privateKey);
        }

        return new Account(privateKey, null);
    }

    /**
     * Creates an account from a private key.
     *
     * @param privateKey the 32-byte private key
     * @return an Account instance
     * @throws IllegalArgumentException if the private key is invalid
     */
    public static Account fromPrivateKey(byte[] privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (privateKey.length != 32) {
            throw new IllegalArgumentException(
                "Private key must be 32 bytes, got " + privateKey.length);
        }

        BigInteger keyInt = new BigInteger(1, privateKey);
        if (keyInt.equals(BigInteger.ZERO) || keyInt.compareTo(CURVE.getN()) >= 0) {
            throw new IllegalArgumentException("Invalid private key value");
        }

        return new Account(privateKey, null);
    }

    /**
     * Creates an account from a hex-encoded private key.
     *
     * @param hex the hex-encoded private key (with or without 0x prefix)
     * @return an Account instance
     * @throws IllegalArgumentException if the hex is invalid
     */
    public static Account fromPrivateKeyHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            throw new IllegalArgumentException("Private key hex cannot be null or empty");
        }

        byte[] privateKey = Hex.toBytes(hex);
        return fromPrivateKey(privateKey);
    }

    /**
     * Creates an account from a mnemonic phrase.
     *
     * @param mnemonic the BIP-39 mnemonic phrase
     * @return an Account instance
     */
    // audit-fix JAVA-CRIT-1: Changed default derivation path from Ethereum's
    // m/44'/60'/0'/0/0 to Quantaureum's registered SLIP-44 path m/44'/1668'/0'/0/0.
    // Using coin type 60 (Ethereum) meant all keys derived from mnemonics were
    // identical to Ethereum wallets, creating a collision risk where the same
    // mnemonic controls both ETH and QAU funds — a major replay/cross-chain attack.
    public static Account fromMnemonic(String mnemonic) {
        return fromMnemonic(mnemonic, "m/44'/1668'/0'/0/0");
    }

    /**
     * Creates an account from a mnemonic phrase with a custom derivation path.
     *
     * @param mnemonic the BIP-39 mnemonic phrase
     * @param path the derivation path
     * @return an Account instance
     */
    public static Account fromMnemonic(String mnemonic, String path) {
        if (mnemonic == null || mnemonic.trim().isEmpty()) {
            throw new IllegalArgumentException("Mnemonic cannot be null or empty");
        }

        byte[] privateKey = MnemonicUtils.derivePrivateKey(mnemonic, path);
        return new Account(privateKey, mnemonic);
    }

    /**
     * Generates a new 12-word mnemonic phrase.
     *
     * @return a new BIP-39 mnemonic phrase
     */
    public static String generateMnemonic() {
        return generateMnemonic(12);
    }

    /**
     * Generates a new mnemonic phrase with the specified word count.
     *
     * @param wordCount the number of words (12, 15, 18, 21, or 24)
     * @return a new BIP-39 mnemonic phrase
     */
    public static String generateMnemonic(int wordCount) {
        return MnemonicUtils.generateMnemonic(wordCount);
    }

    /**
     * Gets the account address.
     *
     * @return the address
     */
    public Address getAddress() {
        return address;
    }

    /**
     * Gets the private key bytes.
     *
     * @return a copy of the private key
     */
    public byte[] getPrivateKey() {
        return privateKey.clone();
    }

    /**
     * Gets the private key as a hex string.
     *
     * @return the hex-encoded private key with 0x prefix
     */
    public String getPrivateKeyHex() {
        return "0x" + Hex.toHexString(privateKey);
    }

    /**
     * Gets the mnemonic phrase if available.
     *
     * @return the mnemonic phrase
     */
    public Optional<String> getMnemonic() {
        return Optional.ofNullable(mnemonic);
    }

    /**
     * Signs a message.
     *
     * @param message the message to sign
     * @return the signature
     */
    public Signature signMessage(byte[] message) {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        // audit-fix JAVA-CRIT-3: Changed prefix from "Ethereum Signed Message"
        // to "Quantaureum Signed Message" to match the blockchain's identity.
        // Using Ethereum's prefix meant signatures were interchangeable with
        // Ethereum wallets, enabling cross-chain replay attacks.
        byte[] prefix = ("\u0019Quantaureum Signed Message:\n" + message.length).getBytes();
        byte[] prefixedMessage = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, prefixedMessage, 0, prefix.length);
        System.arraycopy(message, 0, prefixedMessage, prefix.length, message.length);

        byte[] hash = Keccak256.hash(prefixedMessage);
        return signHash(hash);
    }

    /**
     * Signs a hash directly (without message prefix).
     *
     * @param hash the 32-byte hash to sign
     * @return the signature
     */
    public Signature signHash(byte[] hash) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }

        try {
            ECDSASigner signer = new ECDSASigner();
            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(
                new BigInteger(1, privateKey), CURVE);
            signer.init(true, privKey);

            BigInteger[] signature = signer.generateSignature(hash);
            BigInteger r = signature[0];
            BigInteger s = signature[1];

            // Ensure low S value (EIP-2)
            if (s.compareTo(HALF_CURVE_ORDER) > 0) {
                s = CURVE.getN().subtract(s);
            }

            // Calculate recovery id
            int recId = -1;
            for (int i = 0; i < 4; i++) {
                Address recovered = recoverAddress(hash, r, s, i);
                if (recovered != null && recovered.equals(address)) {
                    recId = i;
                    break;
                }
            }

            if (recId == -1) {
                throw new SigningException("Could not determine recovery id");
            }

            return new Signature(
                bigIntegerToBytes(r, 32),
                bigIntegerToBytes(s, 32),
                recId + 27
            );
        } catch (Exception e) {
            throw new SigningException("Failed to sign hash", e);
        }
    }

    /**
     * Signs a transaction.
     *
     * @param tx the transaction request
     * @param chainId the chain ID
     * @return the signed transaction
     */
    public SignedTransaction signTransaction(TransactionRequest tx, BigInteger chainId) {
        if (tx == null) {
            throw new IllegalArgumentException("Transaction cannot be null");
        }
        if (chainId == null) {
            throw new IllegalArgumentException("Chain ID cannot be null");
        }

        return SignedTransaction.sign(tx, this, chainId);
    }

    /**
     * Signs a hash using Dilithium3 post-quantum signature algorithm.
     *
     * <p>audit-fix JAVA-CRIT-2: Added Dilithium3 signing method for quantum-
     * resistant signatures. ECDSA (secp256k1) is vulnerable to quantum attacks
     * via Shor's algorithm. All new Quantaureum transactions should use
     * Dilithium3 signatures for forward-looking quantum security.</p>
     *
     * @param hash the 32-byte hash to sign
     * @return the Dilithium3 signature
     * @throws SigningException if signing fails
     */
    public Dilithium3Signature signHashDilithium3(byte[] hash) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }
        try {
            return Dilithium3.sign(hash, this.privateKey);
        } catch (Exception e) {
            throw new SigningException("Failed to sign with Dilithium3", e);
        }
    }

    /**
     * Signs a message using Dilithium3 post-quantum signature algorithm.
     *
     * @param message the message to sign
     * @return the Dilithium3 signature
     * @throws SigningException if signing fails
     */
    public Dilithium3Signature signMessageDilithium3(byte[] message) {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        byte[] prefix = ("\u0019Quantaureum Signed Message:\n" + message.length).getBytes();
        byte[] prefixedMessage = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, prefixedMessage, 0, prefix.length);
        System.arraycopy(message, 0, prefixedMessage, prefix.length, message.length);

        byte[] hash = Keccak256.hash(prefixedMessage);
        return signHashDilithium3(hash);
    }

    private static Address deriveAddress(byte[] privateKey) {
        ECPoint pubPoint = new FixedPointCombMultiplier()
            .multiply(CURVE.getG(), new BigInteger(1, privateKey));
        byte[] pubBytes = pubPoint.getEncoded(false);

        // Remove the 0x04 prefix
        byte[] pubKeyBytes = Arrays.copyOfRange(pubBytes, 1, pubBytes.length);

        // Keccak256 hash and take last 20 bytes
        byte[] hash = Keccak256.hash(pubKeyBytes);
        byte[] addressBytes = Arrays.copyOfRange(hash, 12, 32);

        return Address.fromBytes(addressBytes);
    }

    private Address recoverAddress(byte[] hash, BigInteger r, BigInteger s, int recId) {
        try {
            BigInteger n = CURVE.getN();
            BigInteger i = BigInteger.valueOf((long) recId / 2);
            BigInteger x = r.add(i.multiply(n));

            if (x.compareTo(CURVE_PARAMS.getCurve().getField().getCharacteristic()) >= 0) {
                return null;
            }

            ECPoint R = decompressKey(x, (recId & 1) == 1);
            if (!R.multiply(n).isInfinity()) {
                return null;
            }

            BigInteger e = new BigInteger(1, hash);
            BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
            BigInteger rInv = r.modInverse(n);
            BigInteger srInv = rInv.multiply(s).mod(n);
            BigInteger eInvrInv = rInv.multiply(eInv).mod(n);

            ECPoint q = CURVE.getG().multiply(eInvrInv).add(R.multiply(srInv));
            byte[] pubBytes = q.getEncoded(false);
            byte[] pubKeyBytes = Arrays.copyOfRange(pubBytes, 1, pubBytes.length);
            byte[] hashBytes = Keccak256.hash(pubKeyBytes);
            byte[] addressBytes = Arrays.copyOfRange(hashBytes, 12, 32);

            return Address.fromBytes(addressBytes);
        } catch (Exception e) {
            return null;
        }
    }

    private ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        byte[] compEnc = new byte[33];
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        byte[] xBytes = bigIntegerToBytes(xBN, 32);
        System.arraycopy(xBytes, 0, compEnc, 1, 32);
        return CURVE.getCurve().decodePoint(compEnc);
    }

    private static byte[] bigIntegerToBytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }

        byte[] result = new byte[length];
        if (bytes.length > length) {
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        } else {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        }
        return result;
    }
}
