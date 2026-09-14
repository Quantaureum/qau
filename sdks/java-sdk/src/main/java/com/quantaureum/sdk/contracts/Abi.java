// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.contracts;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.quantaureum.sdk.exceptions.AbiException;
import com.quantaureum.sdk.utils.Hex;
import com.quantaureum.sdk.utils.Keccak256;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * ABI (Application Binary Interface) encoder and decoder for smart contract interaction.
 * Supports encoding function calls and decoding return values.
 */
public class Abi {
    private static final ObjectMapper mapper = new ObjectMapper();

    private final List<AbiFunction> functions;
    private final List<AbiEvent> events;
    private final Map<String, AbiFunction> functionsByName;
    private final Map<String, AbiFunction> functionsBySelector;
    private final Map<String, AbiEvent> eventsByName;
    private final Map<String, AbiEvent> eventsByTopic;

    /**
     * Parse ABI from JSON string.
     */
    public static Abi fromJson(String json) throws AbiException {
        try {
            JsonNode root = mapper.readTree(json);
            List<AbiFunction> functions = new ArrayList<>();
            List<AbiEvent> events = new ArrayList<>();

            for (JsonNode item : root) {
                String type = item.has("type") ? item.get("type").asText() : "function";

                if ("function".equals(type) || "constructor".equals(type) || "fallback".equals(type) || "receive".equals(type)) {
                    functions.add(parseFunction(item));
                } else if ("event".equals(type)) {
                    events.add(parseEvent(item));
                }
            }

            return new Abi(functions, events);
        } catch (Exception e) {
            throw new AbiException("Failed to parse ABI JSON: " + e.getMessage(), e);
        }
    }


    private Abi(List<AbiFunction> functions, List<AbiEvent> events) {
        this.functions = Collections.unmodifiableList(functions);
        this.events = Collections.unmodifiableList(events);
        this.functionsByName = new HashMap<>();
        this.functionsBySelector = new HashMap<>();
        this.eventsByName = new HashMap<>();
        this.eventsByTopic = new HashMap<>();

        for (AbiFunction fn : functions) {
            if (fn.getName() != null) {
                functionsByName.put(fn.getName(), fn);
                functionsBySelector.put(fn.getSelector(), fn);
            }
        }

        for (AbiEvent ev : events) {
            eventsByName.put(ev.getName(), ev);
            eventsByTopic.put(ev.getTopic(), ev);
        }
    }

    private static AbiFunction parseFunction(JsonNode node) {
        String name = node.has("name") ? node.get("name").asText() : null;
        String type = node.has("type") ? node.get("type").asText() : "function";
        List<AbiParam> inputs = parseParams(node.get("inputs"));
        List<AbiParam> outputs = parseParams(node.get("outputs"));
        String stateMutability = node.has("stateMutability") ? node.get("stateMutability").asText() : "nonpayable";

        return new AbiFunction(name, type, inputs, outputs, stateMutability);
    }

    private static AbiEvent parseEvent(JsonNode node) {
        String name = node.get("name").asText();
        List<AbiParam> inputs = parseParams(node.get("inputs"));
        boolean anonymous = node.has("anonymous") && node.get("anonymous").asBoolean();

        return new AbiEvent(name, inputs, anonymous);
    }

    private static List<AbiParam> parseParams(JsonNode paramsNode) {
        List<AbiParam> params = new ArrayList<>();
        if (paramsNode != null && paramsNode.isArray()) {
            for (JsonNode param : paramsNode) {
                String name = param.has("name") ? param.get("name").asText() : "";
                String type = param.get("type").asText();
                boolean indexed = param.has("indexed") && param.get("indexed").asBoolean();
                params.add(new AbiParam(name, type, indexed));
            }
        }
        return params;
    }

    /**
     * Get function by name.
     */
    public AbiFunction getFunction(String name) {
        return functionsByName.get(name);
    }

    /**
     * Get function by 4-byte selector.
     */
    public AbiFunction getFunctionBySelector(String selector) {
        return functionsBySelector.get(selector.toLowerCase());
    }

    /**
     * Get event by name.
     */
    public AbiEvent getEvent(String name) {
        return eventsByName.get(name);
    }

    /**
     * Get event by topic hash.
     */
    public AbiEvent getEventByTopic(String topic) {
        return eventsByTopic.get(topic.toLowerCase());
    }

    /**
     * Encode function call with arguments.
     */
    public byte[] encodeFunction(String functionName, Object... args) throws AbiException {
        AbiFunction fn = functionsByName.get(functionName);
        if (fn == null) {
            throw new AbiException("Function not found: " + functionName);
        }
        return fn.encode(args);
    }

    /**
     * Encode function call and return as hex string.
     */
    public String encodeFunctionHex(String functionName, Object... args) throws AbiException {
        return "0x" + Hex.toHexString(encodeFunction(functionName, args));
    }

    /**
     * Decode function return value.
     */
    public Object[] decodeReturn(String functionName, byte[] data) throws AbiException {
        AbiFunction fn = functionsByName.get(functionName);
        if (fn == null) {
            throw new AbiException("Function not found: " + functionName);
        }
        return fn.decodeReturn(data);
    }

    /**
     * Decode function return value from hex string.
     */
    public Object[] decodeReturnHex(String functionName, String hexData) throws AbiException {
        return decodeReturn(functionName, Hex.toBytes(hexData));
    }

    public List<AbiFunction> getFunctions() {
        return functions;
    }

    public List<AbiEvent> getEvents() {
        return events;
    }


    /**
     * Represents an ABI function definition.
     */
    public static class AbiFunction {
        private final String name;
        private final String type;
        private final List<AbiParam> inputs;
        private final List<AbiParam> outputs;
        private final String stateMutability;
        private final String selector;

        AbiFunction(String name, String type, List<AbiParam> inputs, List<AbiParam> outputs, String stateMutability) {
            this.name = name;
            this.type = type;
            this.inputs = inputs;
            this.outputs = outputs;
            this.stateMutability = stateMutability;
            this.selector = name != null ? computeSelector(name, inputs) : null;
        }

        private static String computeSelector(String name, List<AbiParam> inputs) {
            StringBuilder sig = new StringBuilder(name).append("(");
            for (int i = 0; i < inputs.size(); i++) {
                if (i > 0) sig.append(",");
                sig.append(inputs.get(i).getType());
            }
            sig.append(")");
            byte[] hash = Keccak256.hash(sig.toString().getBytes(StandardCharsets.UTF_8));
            return Hex.toHexString(Arrays.copyOf(hash, 4));
        }

        public byte[] encode(Object... args) throws AbiException {
            if (args.length != inputs.size()) {
                throw new AbiException("Expected " + inputs.size() + " arguments, got " + args.length);
            }

            byte[] selectorBytes = Hex.toBytes(selector);
            byte[] encodedArgs = AbiEncoder.encode(inputs, args);

            byte[] result = new byte[4 + encodedArgs.length];
            System.arraycopy(selectorBytes, 0, result, 0, 4);
            System.arraycopy(encodedArgs, 0, result, 4, encodedArgs.length);

            return result;
        }

        public Object[] decodeReturn(byte[] data) throws AbiException {
            return AbiEncoder.decode(outputs, data);
        }

        public String getName() { return name; }
        public String getType() { return type; }
        public List<AbiParam> getInputs() { return inputs; }
        public List<AbiParam> getOutputs() { return outputs; }
        public String getStateMutability() { return stateMutability; }
        public String getSelector() { return selector; }
        public boolean isView() { return "view".equals(stateMutability) || "pure".equals(stateMutability); }
        public boolean isPayable() { return "payable".equals(stateMutability); }
    }

    /**
     * Represents an ABI event definition.
     */
    public static class AbiEvent {
        private final String name;
        private final List<AbiParam> inputs;
        private final boolean anonymous;
        private final String topic;

        AbiEvent(String name, List<AbiParam> inputs, boolean anonymous) {
            this.name = name;
            this.inputs = inputs;
            this.anonymous = anonymous;
            this.topic = computeTopic(name, inputs);
        }

        private static String computeTopic(String name, List<AbiParam> inputs) {
            StringBuilder sig = new StringBuilder(name).append("(");
            for (int i = 0; i < inputs.size(); i++) {
                if (i > 0) sig.append(",");
                sig.append(inputs.get(i).getType());
            }
            sig.append(")");
            return Keccak256.hashToHex(sig.toString().getBytes(StandardCharsets.UTF_8));
        }

        public String getName() { return name; }
        public List<AbiParam> getInputs() { return inputs; }
        public boolean isAnonymous() { return anonymous; }
        public String getTopic() { return topic; }
    }

    /**
     * Represents an ABI parameter.
     */
    public static class AbiParam {
        private final String name;
        private final String type;
        private final boolean indexed;

        AbiParam(String name, String type, boolean indexed) {
            this.name = name;
            this.type = type;
            this.indexed = indexed;
        }

        public String getName() { return name; }
        public String getType() { return type; }
        public boolean isIndexed() { return indexed; }
    }
}
