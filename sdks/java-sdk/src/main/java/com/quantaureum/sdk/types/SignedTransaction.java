// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.types;

import com.quantaureum.sdk.accounts.Account;
import com.quantaureum.sdk.accounts.Signature;
import com.quantaureum.sdk.utils.Hex;
import com.quantaureum.sdk.utils.Keccak256;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a signed transaction.
 */
public class SignedTransaction {

    private final BigInteger nonce;
    private final BigInteger gasPrice;
    private final BigInteger gas;
    private final Address to;
    private final BigInteger value;
    private final byte[] data;
    private final BigInteger v;
    private final BigInteger r;
    private final BigInteger s;

    public SignedTransaction(BigInteger nonce, BigInteger gasPrice, BigInteger gas,
                            Address to, BigInteger value, byte[] data,
                            BigInteger v, BigInteger r, BigInteger s) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gas = gas;
        this.to = to;
        this.value = value;
        this.data = data != null ? data.clone() : new byte[0];
        this.v = v;
        this.r = r;
        this.s = s;
    }

    public static SignedTransaction sign(TransactionRequest tx, Account account, BigInteger chainId) {
        BigInteger nonce = tx.getNonce().orElse(BigInteger.ZERO);
        BigInteger gasPrice = tx.getGasPrice().orElse(BigInteger.ZERO);
        BigInteger gas = tx.getGas().orElse(BigInteger.valueOf(21000));
        Address to = tx.getTo().orElse(null);
        BigInteger value = tx.getValue().orElse(BigInteger.ZERO);
        byte[] data = tx.getData().orElse(new byte[0]);

        // Create unsigned transaction hash (EIP-155)
        byte[] unsignedHash = hashForSigning(nonce, gasPrice, gas, to, value, data, chainId);

        // Sign the hash
        Signature sig = account.signHash(unsignedHash);

        // Calculate EIP-155 v value
        BigInteger v = BigInteger.valueOf(sig.getV() - 27)
            .add(chainId.multiply(BigInteger.valueOf(2)))
            .add(BigInteger.valueOf(35));

        return new SignedTransaction(
            nonce, gasPrice, gas, to, value, data,
            v, sig.getRBigInteger(), sig.getSBigInteger()
        );
    }

    private static byte[] hashForSigning(BigInteger nonce, BigInteger gasPrice, BigInteger gas,
                                         Address to, BigInteger value, byte[] data, BigInteger chainId) {
        List<byte[]> elements = new ArrayList<>();
        elements.add(rlpEncodeBigInteger(nonce));
        elements.add(rlpEncodeBigInteger(gasPrice));
        elements.add(rlpEncodeBigInteger(gas));
        elements.add(to != null ? rlpEncodeBytes(to.toBytes()) : rlpEncodeBytes(new byte[0]));
        elements.add(rlpEncodeBigInteger(value));
        elements.add(rlpEncodeBytes(data));
        elements.add(rlpEncodeBigInteger(chainId));
        elements.add(rlpEncodeBigInteger(BigInteger.ZERO));
        elements.add(rlpEncodeBigInteger(BigInteger.ZERO));

        byte[] rlp = rlpEncodeList(elements);
        return Keccak256.hash(rlp);
    }

    public byte[] encode() {
        List<byte[]> elements = new ArrayList<>();
        elements.add(rlpEncodeBigInteger(nonce));
        elements.add(rlpEncodeBigInteger(gasPrice));
        elements.add(rlpEncodeBigInteger(gas));
        elements.add(to != null ? rlpEncodeBytes(to.toBytes()) : rlpEncodeBytes(new byte[0]));
        elements.add(rlpEncodeBigInteger(value));
        elements.add(rlpEncodeBytes(data));
        elements.add(rlpEncodeBigInteger(v));
        elements.add(rlpEncodeBigInteger(r));
        elements.add(rlpEncodeBigInteger(s));

        return rlpEncodeList(elements);
    }

    public String encodeHex() {
        return "0x" + Hex.toHexString(encode());
    }

    public Hash hash() {
        return Hash.fromBytes(Keccak256.hash(encode()));
    }

    public Address recoverSigner() {
        // Calculate recovery id from v
        BigInteger chainId = v.subtract(BigInteger.valueOf(35)).divide(BigInteger.valueOf(2));
        int recId = v.subtract(chainId.multiply(BigInteger.valueOf(2))).subtract(BigInteger.valueOf(35)).intValue();

        byte[] unsignedHash = hashForSigning(nonce, gasPrice, gas, to, value, data, chainId);

        Signature sig = new Signature(
            bigIntegerToBytes(r, 32),
            bigIntegerToBytes(s, 32),
            recId + 27
        );

        return sig.recoverFromHash(unsignedHash);
    }

    // Getters
    public BigInteger getNonce() { return nonce; }
    public BigInteger getGasPrice() { return gasPrice; }
    public BigInteger getGas() { return gas; }
    public Address getTo() { return to; }
    public BigInteger getValue() { return value; }
    public byte[] getData() { return data.clone(); }
    public BigInteger getV() { return v; }
    public BigInteger getR() { return r; }
    public BigInteger getS() { return s; }

    // Simple RLP encoding helpers
    private static byte[] rlpEncodeBigInteger(BigInteger value) {
        if (value.equals(BigInteger.ZERO)) {
            return new byte[]{(byte) 0x80};
        }
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }
        return rlpEncodeBytes(bytes);
    }

    private static byte[] rlpEncodeBytes(byte[] bytes) {
        if (bytes.length == 0) {
            return new byte[]{(byte) 0x80};
        }
        if (bytes.length == 1 && (bytes[0] & 0xFF) < 0x80) {
            return bytes;
        }
        if (bytes.length <= 55) {
            byte[] result = new byte[bytes.length + 1];
            result[0] = (byte) (0x80 + bytes.length);
            System.arraycopy(bytes, 0, result, 1, bytes.length);
            return result;
        }
        byte[] lenBytes = bigIntegerToBytes(BigInteger.valueOf(bytes.length), 0);
        byte[] result = new byte[1 + lenBytes.length + bytes.length];
        result[0] = (byte) (0xb7 + lenBytes.length);
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(bytes, 0, result, 1 + lenBytes.length, bytes.length);
        return result;
    }

    private static byte[] rlpEncodeList(List<byte[]> elements) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] element : elements) {
            baos.write(element, 0, element.length);
        }
        byte[] payload = baos.toByteArray();

        if (payload.length <= 55) {
            byte[] result = new byte[payload.length + 1];
            result[0] = (byte) (0xc0 + payload.length);
            System.arraycopy(payload, 0, result, 1, payload.length);
            return result;
        }

        byte[] lenBytes = bigIntegerToBytes(BigInteger.valueOf(payload.length), 0);
        byte[] result = new byte[1 + lenBytes.length + payload.length];
        result[0] = (byte) (0xf7 + lenBytes.length);
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(payload, 0, result, 1 + lenBytes.length, payload.length);
        return result;
    }

    private static byte[] bigIntegerToBytes(BigInteger value, int minLength) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0 && bytes.length > 1) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }
        if (minLength > 0 && bytes.length < minLength) {
            byte[] result = new byte[minLength];
            System.arraycopy(bytes, 0, result, minLength - bytes.length, bytes.length);
            return result;
        }
        return bytes;
    }
}
