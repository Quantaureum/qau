// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.accounts;

import com.quantaureum.sdk.types.Address;
import com.quantaureum.sdk.utils.Hex;
import com.quantaureum.sdk.utils.Keccak256;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Represents an ECDSA signature.
 */
public class Signature {

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
        CURVE_PARAMS.getCurve(),
        CURVE_PARAMS.getG(),
        CURVE_PARAMS.getN(),
        CURVE_PARAMS.getH()
    );

    private final byte[] r;
    private final byte[] s;
    private final int v;

    /**
     * Creates a new signature.
     *
     * @param r the r component (32 bytes)
     * @param s the s component (32 bytes)
     * @param v the recovery id (27 or 28)
     */
    public Signature(byte[] r, byte[] s, int v) {
        if (r == null || r.length != 32) {
            throw new IllegalArgumentException("R must be 32 bytes");
        }
        if (s == null || s.length != 32) {
            throw new IllegalArgumentException("S must be 32 bytes");
        }

        this.r = r.clone();
        this.s = s.clone();
        this.v = v;
    }

    /**
     * Gets the R component.
     *
     * @return a copy of R
     */
    public byte[] getR() {
        return r.clone();
    }

    /**
     * Gets the S component.
     *
     * @return a copy of S
     */
    public byte[] getS() {
        return s.clone();
    }

    /**
     * Gets the V value.
     *
     * @return the V value
     */
    public int getV() {
        return v;
    }

    /**
     * Gets the R component as BigInteger.
     *
     * @return R as BigInteger
     */
    public BigInteger getRBigInteger() {
        return new BigInteger(1, r);
    }

    /**
     * Gets the S component as BigInteger.
     *
     * @return S as BigInteger
     */
    public BigInteger getSBigInteger() {
        return new BigInteger(1, s);
    }

    /**
     * Converts the signature to a 65-byte array (r + s + v).
     *
     * @return the signature bytes
     */
    public byte[] toBytes() {
        byte[] result = new byte[65];
        System.arraycopy(r, 0, result, 0, 32);
        System.arraycopy(s, 0, result, 32, 32);
        result[64] = (byte) v;
        return result;
    }

    /**
     * Converts the signature to a hex string.
     *
     * @return the hex-encoded signature with 0x prefix
     */
    public String toHex() {
        return "0x" + Hex.toHexString(toBytes());
    }

    /**
     * Creates a signature from a 65-byte array.
     *
     * @param bytes the signature bytes
     * @return a Signature instance
     */
    public static Signature fromBytes(byte[] bytes) {
        if (bytes == null || bytes.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }

        byte[] r = Arrays.copyOfRange(bytes, 0, 32);
        byte[] s = Arrays.copyOfRange(bytes, 32, 64);
        int v = bytes[64] & 0xFF;

        return new Signature(r, s, v);
    }

    /**
     * Creates a signature from a hex string.
     *
     * @param hex the hex-encoded signature
     * @return a Signature instance
     */
    public static Signature fromHex(String hex) {
        return fromBytes(Hex.toBytes(hex));
    }

    /**
     * Recovers the signer address from a message.
     *
     * @param message the original message
     * @return the signer address
     */
    public Address recover(byte[] message) {
        // Ethereum signed message format
        byte[] prefix = ("\u0019Ethereum Signed Message:\n" + message.length).getBytes();
        byte[] prefixedMessage = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, prefixedMessage, 0, prefix.length);
        System.arraycopy(message, 0, prefixedMessage, prefix.length, message.length);

        byte[] hash = Keccak256.hash(prefixedMessage);
        return recoverFromHash(hash);
    }

    /**
     * Recovers the signer address from a hash.
     *
     * @param hash the 32-byte hash
     * @return the signer address
     */
    public Address recoverFromHash(byte[] hash) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }

        int recId = v >= 27 ? v - 27 : v;

        BigInteger rBig = new BigInteger(1, r);
        BigInteger sBig = new BigInteger(1, s);
        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = rBig.add(i.multiply(n));

        if (x.compareTo(CURVE_PARAMS.getCurve().getField().getCharacteristic()) >= 0) {
            throw new IllegalArgumentException("Invalid signature");
        }

        ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity()) {
            throw new IllegalArgumentException("Invalid signature");
        }

        BigInteger e = new BigInteger(1, hash);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = rBig.modInverse(n);
        BigInteger srInv = rInv.multiply(sBig).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);

        ECPoint q = CURVE.getG().multiply(eInvrInv).add(R.multiply(srInv));
        byte[] pubBytes = q.getEncoded(false);
        byte[] pubKeyBytes = Arrays.copyOfRange(pubBytes, 1, pubBytes.length);
        byte[] hashBytes = Keccak256.hash(pubKeyBytes);
        byte[] addressBytes = Arrays.copyOfRange(hashBytes, 12, 32);

        return Address.fromBytes(addressBytes);
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
