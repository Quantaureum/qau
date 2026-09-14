// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.contracts;

import com.quantaureum.sdk.exceptions.AbiException;
import com.quantaureum.sdk.types.Address;
import com.quantaureum.sdk.utils.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * ABI encoding and decoding utilities for Solidity types.
 */
public class AbiEncoder {
    private static final int WORD_SIZE = 32;

    /**
     * Encode parameters according to ABI specification.
     */
    public static byte[] encode(List<Abi.AbiParam> params, Object[] values) throws AbiException {
        if (params.size() != values.length) {
            throw new AbiException("Parameter count mismatch");
        }

        if (params.isEmpty()) {
            return new byte[0];
        }

        // Calculate head and tail sizes
        int headSize = params.size() * WORD_SIZE;
        byte[][] heads = new byte[params.size()][];
        byte[][] tails = new byte[params.size()][];
        int tailOffset = headSize;

        for (int i = 0; i < params.size(); i++) {
            String type = params.get(i).getType();
            Object value = values[i];

            if (isDynamic(type)) {
                // Dynamic type: head contains offset, tail contains data
                heads[i] = encodeUint256(BigInteger.valueOf(tailOffset));
                tails[i] = encodeDynamic(type, value);
                tailOffset += tails[i].length;
            } else {
                // Static type: head contains data directly
                heads[i] = encodeStatic(type, value);
                tails[i] = new byte[0];
            }
        }

        // Combine heads and tails
        byte[] result = new byte[tailOffset];
        int offset = 0;
        for (byte[] head : heads) {
            System.arraycopy(head, 0, result, offset, head.length);
            offset += head.length;
        }
        for (byte[] tail : tails) {
            System.arraycopy(tail, 0, result, offset, tail.length);
            offset += tail.length;
        }

        return result;
    }

    /**
     * Decode return values according to ABI specification.
     */
    public static Object[] decode(List<Abi.AbiParam> params, byte[] data) throws AbiException {
        if (params.isEmpty()) {
            return new Object[0];
        }

        Object[] results = new Object[params.size()];
        int offset = 0;

        for (int i = 0; i < params.size(); i++) {
            String type = params.get(i).getType();

            if (isDynamic(type)) {
                // Read offset from head
                BigInteger dataOffset = decodeUint256(data, offset);
                results[i] = decodeDynamic(type, data, dataOffset.intValue());
            } else {
                results[i] = decodeStatic(type, data, offset);
            }
            offset += WORD_SIZE;
        }

        return results;
    }


    private static boolean isDynamic(String type) {
        return type.equals("string") || type.equals("bytes") || type.endsWith("[]");
    }

    private static byte[] encodeStatic(String type, Object value) throws AbiException {
        if (type.equals("address")) {
            return encodeAddress(value);
        } else if (type.equals("bool")) {
            return encodeBool(value);
        } else if (type.startsWith("uint")) {
            return encodeUint(type, value);
        } else if (type.startsWith("int")) {
            return encodeInt(type, value);
        } else if (type.startsWith("bytes") && !type.equals("bytes")) {
            return encodeFixedBytes(type, value);
        }
        throw new AbiException("Unsupported type: " + type);
    }

    private static byte[] encodeDynamic(String type, Object value) throws AbiException {
        if (type.equals("string")) {
            return encodeString(value);
        } else if (type.equals("bytes")) {
            return encodeBytes(value);
        } else if (type.endsWith("[]")) {
            return encodeArray(type, value);
        }
        throw new AbiException("Unsupported dynamic type: " + type);
    }

    private static Object decodeStatic(String type, byte[] data, int offset) throws AbiException {
        if (type.equals("address")) {
            return decodeAddress(data, offset);
        } else if (type.equals("bool")) {
            return decodeBool(data, offset);
        } else if (type.startsWith("uint")) {
            return decodeUint256(data, offset);
        } else if (type.startsWith("int")) {
            return decodeInt256(data, offset);
        } else if (type.startsWith("bytes") && !type.equals("bytes")) {
            return decodeFixedBytes(type, data, offset);
        }
        throw new AbiException("Unsupported type: " + type);
    }

    private static Object decodeDynamic(String type, byte[] data, int offset) throws AbiException {
        if (type.equals("string")) {
            return decodeString(data, offset);
        } else if (type.equals("bytes")) {
            return decodeDynamicBytes(data, offset);
        }
        throw new AbiException("Unsupported dynamic type: " + type);
    }

    // Encoding methods
    private static byte[] encodeAddress(Object value) throws AbiException {
        byte[] addressBytes;
        if (value instanceof Address) {
            addressBytes = ((Address) value).toBytes();
        } else if (value instanceof String) {
            addressBytes = Address.fromHex((String) value).toBytes();
        } else if (value instanceof byte[]) {
            addressBytes = (byte[]) value;
        } else {
            throw new AbiException("Invalid address value: " + value);
        }
        return padLeft(addressBytes, WORD_SIZE);
    }

    private static byte[] encodeBool(Object value) {
        boolean b = value instanceof Boolean ? (Boolean) value : Boolean.parseBoolean(value.toString());
        return encodeUint256(b ? BigInteger.ONE : BigInteger.ZERO);
    }

    private static byte[] encodeUint(String type, Object value) throws AbiException {
        BigInteger bi = toBigInteger(value);
        if (bi.signum() < 0) {
            throw new AbiException("Negative value for unsigned type: " + bi);
        }
        return encodeUint256(bi);
    }

    private static byte[] encodeInt(String type, Object value) throws AbiException {
        BigInteger bi = toBigInteger(value);
        return encodeInt256(bi);
    }

    private static byte[] encodeUint256(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > WORD_SIZE) {
            // Remove leading zero byte if present
            if (bytes[0] == 0 && bytes.length == WORD_SIZE + 1) {
                bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
            }
        }
        return padLeft(bytes, WORD_SIZE);
    }

    private static byte[] encodeInt256(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte padByte = value.signum() < 0 ? (byte) 0xFF : 0;
        byte[] result = new byte[WORD_SIZE];
        Arrays.fill(result, padByte);
        int srcPos = Math.max(0, bytes.length - WORD_SIZE);
        int destPos = Math.max(0, WORD_SIZE - bytes.length);
        int length = Math.min(bytes.length, WORD_SIZE);
        System.arraycopy(bytes, srcPos, result, destPos, length);
        return result;
    }

    private static byte[] encodeFixedBytes(String type, Object value) throws AbiException {
        int size = Integer.parseInt(type.substring(5));
        byte[] bytes;
        if (value instanceof byte[]) {
            bytes = (byte[]) value;
        } else if (value instanceof String) {
            bytes = Hex.toBytes((String) value);
        } else {
            throw new AbiException("Invalid bytes value: " + value);
        }
        if (bytes.length > size) {
            throw new AbiException("Bytes too long for " + type);
        }
        return padRight(bytes, WORD_SIZE);
    }

    private static byte[] encodeString(Object value) {
        byte[] strBytes = value.toString().getBytes(StandardCharsets.UTF_8);
        return encodeBytesData(strBytes);
    }

    private static byte[] encodeBytes(Object value) throws AbiException {
        byte[] bytes;
        if (value instanceof byte[]) {
            bytes = (byte[]) value;
        } else if (value instanceof String) {
            bytes = Hex.toBytes((String) value);
        } else {
            throw new AbiException("Invalid bytes value: " + value);
        }
        return encodeBytesData(bytes);
    }

    private static byte[] encodeBytesData(byte[] data) {
        int paddedLength = ((data.length + WORD_SIZE - 1) / WORD_SIZE) * WORD_SIZE;
        byte[] result = new byte[WORD_SIZE + paddedLength];
        byte[] lengthEncoded = encodeUint256(BigInteger.valueOf(data.length));
        System.arraycopy(lengthEncoded, 0, result, 0, WORD_SIZE);
        System.arraycopy(data, 0, result, WORD_SIZE, data.length);
        return result;
    }

    private static byte[] encodeArray(String type, Object value) throws AbiException {
        String elementType = type.substring(0, type.length() - 2);
        Object[] array;
        if (value instanceof Object[]) {
            array = (Object[]) value;
        } else if (value instanceof List) {
            array = ((List<?>) value).toArray();
        } else {
            throw new AbiException("Invalid array value: " + value);
        }

        byte[] lengthEncoded = encodeUint256(BigInteger.valueOf(array.length));
        byte[][] elements = new byte[array.length][];
        int totalSize = WORD_SIZE;

        for (int i = 0; i < array.length; i++) {
            elements[i] = encodeStatic(elementType, array[i]);
            totalSize += elements[i].length;
        }

        byte[] result = new byte[totalSize];
        System.arraycopy(lengthEncoded, 0, result, 0, WORD_SIZE);
        int offset = WORD_SIZE;
        for (byte[] element : elements) {
            System.arraycopy(element, 0, result, offset, element.length);
            offset += element.length;
        }
        return result;
    }


    // Decoding methods
    private static BigInteger decodeUint256(byte[] data, int offset) {
        byte[] word = Arrays.copyOfRange(data, offset, offset + WORD_SIZE);
        return new BigInteger(1, word);
    }

    private static BigInteger decodeInt256(byte[] data, int offset) {
        byte[] word = Arrays.copyOfRange(data, offset, offset + WORD_SIZE);
        return new BigInteger(word);
    }

    private static Address decodeAddress(byte[] data, int offset) {
        byte[] addressBytes = Arrays.copyOfRange(data, offset + 12, offset + WORD_SIZE);
        return Address.fromBytes(addressBytes);
    }

    private static Boolean decodeBool(byte[] data, int offset) {
        return data[offset + WORD_SIZE - 1] != 0;
    }

    private static byte[] decodeFixedBytes(String type, byte[] data, int offset) {
        int size = Integer.parseInt(type.substring(5));
        return Arrays.copyOfRange(data, offset, offset + size);
    }

    private static String decodeString(byte[] data, int offset) {
        BigInteger length = decodeUint256(data, offset);
        byte[] strBytes = Arrays.copyOfRange(data, offset + WORD_SIZE, offset + WORD_SIZE + length.intValue());
        return new String(strBytes, StandardCharsets.UTF_8);
    }

    private static byte[] decodeDynamicBytes(byte[] data, int offset) {
        BigInteger length = decodeUint256(data, offset);
        return Arrays.copyOfRange(data, offset + WORD_SIZE, offset + WORD_SIZE + length.intValue());
    }

    // Utility methods
    private static byte[] padLeft(byte[] bytes, int length) {
        if (bytes.length >= length) {
            return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
        }
        byte[] result = new byte[length];
        System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        return result;
    }

    private static byte[] padRight(byte[] bytes, int length) {
        if (bytes.length >= length) {
            return Arrays.copyOf(bytes, length);
        }
        byte[] result = new byte[length];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        return result;
    }

    private static BigInteger toBigInteger(Object value) throws AbiException {
        if (value instanceof BigInteger) {
            return (BigInteger) value;
        } else if (value instanceof Number) {
            return BigInteger.valueOf(((Number) value).longValue());
        } else if (value instanceof String) {
            String s = (String) value;
            if (s.startsWith("0x")) {
                return new BigInteger(s.substring(2), 16);
            }
            return new BigInteger(s);
        }
        throw new AbiException("Cannot convert to BigInteger: " + value);
    }

    /**
     * Encode a single value of the given type.
     */
    public static byte[] encodeSingle(String type, Object value) throws AbiException {
        if (isDynamic(type)) {
            return encodeDynamic(type, value);
        }
        return encodeStatic(type, value);
    }

    /**
     * Decode a single value of the given type.
     */
    public static Object decodeSingle(String type, byte[] data) throws AbiException {
        if (isDynamic(type)) {
            return decodeDynamic(type, data, 0);
        }
        return decodeStatic(type, data, 0);
    }
}
