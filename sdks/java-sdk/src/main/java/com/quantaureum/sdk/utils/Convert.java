// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.utils;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;

/**
 * Utility class for converting between Wei and Ether units.
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Convert Ether to Wei
 * BigInteger wei = Convert.toWei("1.5", Unit.ETHER);
 *
 * // Convert Wei to Ether
 * String ether = Convert.fromWei(wei, Unit.ETHER);
 *
 * // Convert Gwei to Wei
 * BigInteger wei = Convert.toWei("100", Unit.GWEI);
 * }</pre>
 */
public final class Convert {

    private Convert() {
        // Utility class, no instantiation
    }

    /**
     * Ethereum unit denominations.
     */
    public enum Unit {
        WEI(0),
        KWEI(3),
        MWEI(6),
        GWEI(9),
        SZABO(12),
        FINNEY(15),
        ETHER(18);

        private final int decimals;
        private final BigInteger factor;

        Unit(int decimals) {
            this.decimals = decimals;
            this.factor = BigInteger.TEN.pow(decimals);
        }

        public int getDecimals() {
            return decimals;
        }

        public BigInteger getFactor() {
            return factor;
        }
    }

    /**
     * Converts a value from the specified unit to Wei.
     *
     * @param value the value as a string (can include decimals)
     * @param unit the unit to convert from
     * @return the value in Wei
     * @throws IllegalArgumentException if value is invalid
     */
    public static BigInteger toWei(String value, Unit unit) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Value cannot be null or empty");
        }
        if (unit == null) {
            throw new IllegalArgumentException("Unit cannot be null");
        }

        try {
            BigDecimal decimal = new BigDecimal(value.trim());
            BigDecimal wei = decimal.multiply(new BigDecimal(unit.getFactor()));

            // Check for fractional Wei
            if (wei.stripTrailingZeros().scale() > 0) {
                throw new IllegalArgumentException(
                    "Value has too many decimal places for unit " + unit);
            }

            return wei.toBigInteger();
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid number format: " + value, e);
        }
    }

    /**
     * Converts a value from Wei to the specified unit.
     *
     * @param wei the value in Wei
     * @param unit the unit to convert to
     * @return the value as a string
     * @throws IllegalArgumentException if wei is null
     */
    public static String fromWei(BigInteger wei, Unit unit) {
        if (wei == null) {
            throw new IllegalArgumentException("Wei value cannot be null");
        }
        if (unit == null) {
            throw new IllegalArgumentException("Unit cannot be null");
        }

        BigDecimal decimal = new BigDecimal(wei);
        BigDecimal result = decimal.divide(
            new BigDecimal(unit.getFactor()),
            unit.getDecimals(),
            RoundingMode.DOWN
        );

        return result.stripTrailingZeros().toPlainString();
    }

    /**
     * Converts Ether to Wei.
     *
     * @param ether the ether value as a string
     * @return the value in Wei
     */
    public static BigInteger etherToWei(String ether) {
        return toWei(ether, Unit.ETHER);
    }

    /**
     * Converts Wei to Ether.
     *
     * @param wei the value in Wei
     * @return the ether value as a string
     */
    public static String weiToEther(BigInteger wei) {
        return fromWei(wei, Unit.ETHER);
    }

    /**
     * Converts Gwei to Wei.
     *
     * @param gwei the gwei value as a string
     * @return the value in Wei
     */
    public static BigInteger gweiToWei(String gwei) {
        return toWei(gwei, Unit.GWEI);
    }

    /**
     * Converts Wei to Gwei.
     *
     * @param wei the value in Wei
     * @return the gwei value as a string
     */
    public static String weiToGwei(BigInteger wei) {
        return fromWei(wei, Unit.GWEI);
    }
}
