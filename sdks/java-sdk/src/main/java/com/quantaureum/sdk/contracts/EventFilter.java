// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.contracts;

import com.quantaureum.sdk.client.QuantaureumClient;
import com.quantaureum.sdk.exceptions.AbiException;
import com.quantaureum.sdk.exceptions.RpcException;
import com.quantaureum.sdk.types.Address;
import com.quantaureum.sdk.types.Log;
import com.quantaureum.sdk.utils.Hex;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Event filter for querying contract events/logs.
 */
public class EventFilter {
    private final QuantaureumClient client;
    private final Address contractAddress;
    private final Abi.AbiEvent event;

    private String fromBlock = "earliest";
    private String toBlock = "latest";
    private final List<String[]> topics = new ArrayList<>();

    /**
     * Create an event filter.
     *
     * @param client          The Quantaureum client
     * @param contractAddress The contract address
     * @param event           The event definition
     */
    public EventFilter(QuantaureumClient client, Address contractAddress, Abi.AbiEvent event) {
        this.client = client;
        this.contractAddress = contractAddress;
        this.event = event;

        // Add event topic as first topic
        if (!event.isAnonymous()) {
            this.topics.add(new String[]{event.getTopic()});
        }
    }

    /**
     * Set the starting block for the filter.
     *
     * @param blockNumber Block number or "earliest", "latest", "pending"
     */
    public EventFilter fromBlock(String blockNumber) {
        this.fromBlock = blockNumber;
        return this;
    }

    /**
     * Set the starting block for the filter.
     *
     * @param blockNumber Block number
     */
    public EventFilter fromBlock(long blockNumber) {
        this.fromBlock = "0x" + Long.toHexString(blockNumber);
        return this;
    }

    /**
     * Set the ending block for the filter.
     *
     * @param blockNumber Block number or "earliest", "latest", "pending"
     */
    public EventFilter toBlock(String blockNumber) {
        this.toBlock = blockNumber;
        return this;
    }

    /**
     * Set the ending block for the filter.
     *
     * @param blockNumber Block number
     */
    public EventFilter toBlock(long blockNumber) {
        this.toBlock = "0x" + Long.toHexString(blockNumber);
        return this;
    }

    /**
     * Add a topic filter for an indexed parameter.
     * Call this method in order for each indexed parameter.
     *
     * @param values Possible values for this topic (OR condition)
     */
    public EventFilter topic(String... values) {
        if (values == null || values.length == 0) {
            topics.add(null); // null means any value
        } else {
            topics.add(values);
        }
        return this;
    }

    /**
     * Add a topic filter for an indexed address parameter.
     *
     * @param addresses Possible addresses for this topic
     */
    public EventFilter topicAddress(Address... addresses) {
        if (addresses == null || addresses.length == 0) {
            topics.add(null);
        } else {
            String[] values = new String[addresses.length];
            for (int i = 0; i < addresses.length; i++) {
                // Pad address to 32 bytes
                values[i] = "0x" + String.format("%064x", new BigInteger(1, addresses[i].toBytes()));
            }
            topics.add(values);
        }
        return this;
    }

    /**
     * Add a topic filter for an indexed uint256 parameter.
     *
     * @param values Possible values for this topic
     */
    public EventFilter topicUint256(BigInteger... values) {
        if (values == null || values.length == 0) {
            topics.add(null);
        } else {
            String[] hexValues = new String[values.length];
            for (int i = 0; i < values.length; i++) {
                hexValues[i] = "0x" + String.format("%064x", values[i]);
            }
            topics.add(hexValues);
        }
        return this;
    }

    /**
     * Query logs matching this filter.
     *
     * @return List of decoded event logs
     */
    public List<DecodedLog> getLogs() throws RpcException, AbiException {
        List<Log> logs = client.getLogs(
                contractAddress.toHex(),
                fromBlock,
                toBlock,
                buildTopics()
        );

        List<DecodedLog> decodedLogs = new ArrayList<>();
        for (Log log : logs) {
            decodedLogs.add(decodeLog(log));
        }
        return decodedLogs;
    }

    /**
     * Query logs asynchronously.
     */
    public CompletableFuture<List<DecodedLog>> getLogsAsync() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getLogs();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private List<Object> buildTopics() {
        List<Object> result = new ArrayList<>();
        for (String[] topic : topics) {
            if (topic == null) {
                result.add(null);
            } else if (topic.length == 1) {
                result.add(topic[0]);
            } else {
                result.add(Arrays.asList(topic));
            }
        }
        return result;
    }

    private DecodedLog decodeLog(Log log) throws AbiException {
        Map<String, Object> indexed = new HashMap<>();
        Map<String, Object> data = new HashMap<>();

        List<Abi.AbiParam> inputs = event.getInputs();
        List<com.quantaureum.sdk.types.Hash> logTopics = log.getTopics();

        int topicIndex = event.isAnonymous() ? 0 : 1; // Skip event signature topic
        int dataOffset = 0;
        byte[] logData = log.getData();

        for (Abi.AbiParam param : inputs) {
            if (param.isIndexed()) {
                // Indexed parameters are in topics
                if (topicIndex < logTopics.size()) {
                    String topicValue = logTopics.get(topicIndex).toHex();
                    Object decoded = decodeIndexedParam(param.getType(), topicValue);
                    indexed.put(param.getName(), decoded);
                    topicIndex++;
                }
            } else {
                // Non-indexed parameters are in data
                if (dataOffset < logData.length) {
                    Object decoded = AbiEncoder.decodeSingle(param.getType(),
                            Arrays.copyOfRange(logData, dataOffset, logData.length));
                    data.put(param.getName(), decoded);
                    dataOffset += 32; // Each parameter is 32 bytes in ABI encoding
                }
            }
        }

        return new DecodedLog(
                event.getName(),
                log,
                indexed,
                data
        );
    }

    private Object decodeIndexedParam(String type, String topicValue) throws AbiException {
        byte[] bytes = Hex.toBytes(topicValue);

        if (type.equals("address")) {
            // Address is in the last 20 bytes
            byte[] addressBytes = Arrays.copyOfRange(bytes, 12, 32);
            return Address.fromBytes(addressBytes);
        } else if (type.startsWith("uint") || type.startsWith("int")) {
            return new BigInteger(1, bytes);
        } else if (type.equals("bool")) {
            return bytes[31] != 0;
        } else if (type.startsWith("bytes") && !type.equals("bytes")) {
            int size = Integer.parseInt(type.substring(5));
            return Arrays.copyOf(bytes, size);
        }

        // For dynamic types (string, bytes, arrays), the topic contains the hash
        return topicValue;
    }

    /**
     * Represents a decoded event log.
     */
    public static class DecodedLog {
        private final String eventName;
        private final Log rawLog;
        private final Map<String, Object> indexedParams;
        private final Map<String, Object> dataParams;

        public DecodedLog(String eventName, Log rawLog,
                         Map<String, Object> indexedParams, Map<String, Object> dataParams) {
            this.eventName = eventName;
            this.rawLog = rawLog;
            this.indexedParams = Collections.unmodifiableMap(indexedParams);
            this.dataParams = Collections.unmodifiableMap(dataParams);
        }

        public String getEventName() { return eventName; }
        public Log getRawLog() { return rawLog; }
        public Map<String, Object> getIndexedParams() { return indexedParams; }
        public Map<String, Object> getDataParams() { return dataParams; }

        /**
         * Get a parameter by name (searches both indexed and data params).
         */
        public Object get(String name) {
            Object value = indexedParams.get(name);
            if (value == null) {
                value = dataParams.get(name);
            }
            return value;
        }

        @Override
        public String toString() {
            return "DecodedLog{event=" + eventName +
                   ", indexed=" + indexedParams +
                   ", data=" + dataParams + "}";
        }
    }
}
