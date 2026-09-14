// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.quantaureum.sdk.exceptions.RpcException;
import com.quantaureum.sdk.types.Address;
import com.quantaureum.sdk.types.Block;
import com.quantaureum.sdk.types.Hash;
import com.quantaureum.sdk.types.Log;
import com.quantaureum.sdk.types.SignedTransaction;
import com.quantaureum.sdk.types.TransactionReceipt;
import com.quantaureum.sdk.types.TransactionRequest;
import com.quantaureum.sdk.utils.Hex;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Client for interacting with Quantaureum blockchain nodes.
 */
public class QuantaureumClient implements AutoCloseable {

    private static final MediaType JSON = MediaType.parse("application/json");

    private final String url;
    private final OkHttpClient httpClient;
    private final ObjectMapper mapper;
    private final AtomicLong requestId;

    public QuantaureumClient(String url) {
        this(url, ClientConfig.defaults());
    }

    public QuantaureumClient(String url, ClientConfig config) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }

        this.url = url;
        this.mapper = new ObjectMapper();
        this.requestId = new AtomicLong(1);
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(config.getConnectTimeout())
            .readTimeout(config.getReadTimeout())
            .writeTimeout(config.getWriteTimeout())
            .build();
    }

    // Block methods

    public BigInteger getBlockNumber() {
        JsonNode result = call("eth_blockNumber");
        return hexToBigInteger(result.asText());
    }

    public CompletableFuture<BigInteger> getBlockNumberAsync() {
        return callAsync("eth_blockNumber")
            .thenApply(result -> hexToBigInteger(result.asText()));
    }

    public Optional<Block> getBlockByNumber(BigInteger number) {
        String blockParam = number != null ? "0x" + number.toString(16) : "latest";
        JsonNode result = call("eth_getBlockByNumber", blockParam, false);
        return parseBlock(result);
    }

    public Optional<Block> getBlockByHash(Hash hash) {
        JsonNode result = call("eth_getBlockByHash", hash.toHex(), false);
        return parseBlock(result);
    }

    // Transaction methods

    public Optional<TransactionRequest> getTransactionByHash(Hash hash) {
        JsonNode result = call("eth_getTransactionByHash", hash.toHex());
        return parseTransaction(result);
    }

    public Optional<TransactionReceipt> getTransactionReceipt(Hash hash) {
        JsonNode result = call("eth_getTransactionReceipt", hash.toHex());
        return parseReceipt(result);
    }

    public Hash sendTransaction(SignedTransaction tx) {
        String rawTx = tx.encodeHex();
        JsonNode result = call("eth_sendRawTransaction", rawTx);
        return Hash.fromHex(result.asText());
    }

    public CompletableFuture<Hash> sendTransactionAsync(SignedTransaction tx) {
        String rawTx = tx.encodeHex();
        return callAsync("eth_sendRawTransaction", rawTx)
            .thenApply(result -> Hash.fromHex(result.asText()));
    }

    // Account methods

    public BigInteger getBalance(Address address) {
        return getBalance(address, null);
    }

    public BigInteger getBalance(Address address, BigInteger blockNumber) {
        String blockParam = blockNumber != null ? "0x" + blockNumber.toString(16) : "latest";
        JsonNode result = call("eth_getBalance", address.toHex(), blockParam);
        return hexToBigInteger(result.asText());
    }

    public CompletableFuture<BigInteger> getBalanceAsync(Address address) {
        return callAsync("eth_getBalance", address.toHex(), "latest")
            .thenApply(result -> hexToBigInteger(result.asText()));
    }

    public BigInteger getNonce(Address address) {
        JsonNode result = call("eth_getTransactionCount", address.toHex(), "latest");
        return hexToBigInteger(result.asText());
    }

    public BigInteger getPendingNonce(Address address) {
        JsonNode result = call("eth_getTransactionCount", address.toHex(), "pending");
        return hexToBigInteger(result.asText());
    }

    public byte[] getCode(Address address) {
        JsonNode result = call("eth_getCode", address.toHex(), "latest");
        return Hex.toBytes(result.asText());
    }

    // Gas methods

    public BigInteger getGasPrice() {
        JsonNode result = call("eth_gasPrice");
        return hexToBigInteger(result.asText());
    }

    public BigInteger estimateGas(TransactionRequest tx) {
        ObjectNode txObj = mapper.createObjectNode();
        tx.getFrom().ifPresent(from -> txObj.put("from", from.toHex()));
        tx.getTo().ifPresent(to -> txObj.put("to", to.toHex()));
        tx.getGas().ifPresent(gas -> txObj.put("gas", "0x" + gas.toString(16)));
        tx.getGasPrice().ifPresent(gp -> txObj.put("gasPrice", "0x" + gp.toString(16)));
        tx.getValue().ifPresent(v -> txObj.put("value", "0x" + v.toString(16)));
        tx.getData().ifPresent(d -> txObj.put("data", "0x" + Hex.toHexString(d)));

        JsonNode result = call("eth_estimateGas", txObj);
        return hexToBigInteger(result.asText());
    }

    public BigInteger estimateGas(CallRequest request) {
        ObjectNode txObj = mapper.createObjectNode();
        request.getFrom().ifPresent(from -> txObj.put("from", from.toHex()));
        txObj.put("to", request.getTo().toHex());
        request.getGas().ifPresent(gas -> txObj.put("gas", "0x" + gas.toString(16)));
        request.getGasPrice().ifPresent(gp -> txObj.put("gasPrice", "0x" + gp.toString(16)));
        request.getValue().ifPresent(v -> txObj.put("value", "0x" + v.toString(16)));
        request.getData().ifPresent(d -> txObj.put("data", "0x" + Hex.toHexString(d)));

        JsonNode result = call("eth_estimateGas", txObj);
        return hexToBigInteger(result.asText());
    }

    // Call method

    public byte[] call(CallRequest request) {
        return call(request, null);
    }

    public byte[] call(CallRequest request, BigInteger blockNumber) {
        ObjectNode txObj = mapper.createObjectNode();
        request.getFrom().ifPresent(from -> txObj.put("from", from.toHex()));
        txObj.put("to", request.getTo().toHex());
        request.getGas().ifPresent(gas -> txObj.put("gas", "0x" + gas.toString(16)));
        request.getGasPrice().ifPresent(gp -> txObj.put("gasPrice", "0x" + gp.toString(16)));
        request.getValue().ifPresent(v -> txObj.put("value", "0x" + v.toString(16)));
        request.getData().ifPresent(d -> txObj.put("data", "0x" + Hex.toHexString(d)));

        String blockParam = blockNumber != null ? "0x" + blockNumber.toString(16) : "latest";
        JsonNode result = call("eth_call", txObj, blockParam);
        return Hex.toBytes(result.asText());
    }

    // Logs

    public List<Log> getLogs(String address, String fromBlock, String toBlock, List<Object> topics) {
        ObjectNode filterObj = mapper.createObjectNode();
        if (address != null) {
            filterObj.put("address", address);
        }
        filterObj.put("fromBlock", fromBlock);
        filterObj.put("toBlock", toBlock);

        if (topics != null && !topics.isEmpty()) {
            ArrayNode topicsArray = filterObj.putArray("topics");
            for (Object topic : topics) {
                if (topic == null) {
                    topicsArray.addNull();
                } else if (topic instanceof String) {
                    topicsArray.add((String) topic);
                } else if (topic instanceof List) {
                    ArrayNode orArray = topicsArray.addArray();
                    for (Object t : (List<?>) topic) {
                        orArray.add((String) t);
                    }
                }
            }
        }

        JsonNode result = call("eth_getLogs", filterObj);
        List<Log> logs = new ArrayList<>();

        if (result != null && result.isArray()) {
            for (JsonNode logNode : result) {
                List<Hash> logTopics = new ArrayList<>();
                JsonNode topicsNode = logNode.get("topics");
                if (topicsNode != null && topicsNode.isArray()) {
                    for (JsonNode t : topicsNode) {
                        logTopics.add(Hash.fromHex(t.asText()));
                    }
                }

                logs.add(new Log(
                    Address.fromHex(logNode.get("address").asText()),
                    logTopics,
                    Hex.toBytes(logNode.get("data").asText()),
                    hexToBigInteger(logNode.get("blockNumber").asText()),
                    Hash.fromHex(logNode.get("transactionHash").asText()),
                    hexToBigInteger(logNode.get("transactionIndex").asText()),
                    Hash.fromHex(logNode.get("blockHash").asText()),
                    hexToBigInteger(logNode.get("logIndex").asText())
                ));
            }
        }

        return logs;
    }

    // Chain info

    public BigInteger getChainId() {
        JsonNode result = call("eth_chainId");
        return hexToBigInteger(result.asText());
    }

    @Override
    public void close() {
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
    }

    // RPC helpers

    private JsonNode call(String method, Object... params) {
        try {
            ObjectNode request = mapper.createObjectNode();
            request.put("jsonrpc", "2.0");
            request.put("method", method);
            request.put("id", requestId.getAndIncrement());

            ArrayNode paramsArray = request.putArray("params");
            for (Object param : params) {
                if (param instanceof String) {
                    paramsArray.add((String) param);
                } else if (param instanceof Boolean) {
                    paramsArray.add((Boolean) param);
                } else if (param instanceof ObjectNode) {
                    paramsArray.add((ObjectNode) param);
                }
            }

            RequestBody body = RequestBody.create(mapper.writeValueAsString(request), JSON);
            Request httpRequest = new Request.Builder()
                .url(url)
                .post(body)
                .build();

            try (Response response = httpClient.newCall(httpRequest).execute()) {
                if (!response.isSuccessful()) {
                    throw new RpcException("HTTP error: " + response.code(), null);
                }

                JsonNode jsonResponse = mapper.readTree(response.body().string());

                if (jsonResponse.has("error")) {
                    JsonNode error = jsonResponse.get("error");
                    int code = error.get("code").asInt();
                    String message = error.get("message").asText();
                    String data = error.has("data") ? error.get("data").asText() : null;
                    throw new RpcException(code, message, data);
                }

                return jsonResponse.get("result");
            }
        } catch (RpcException e) {
            throw e;
        } catch (IOException e) {
            throw new RpcException("Connection error: " + e.getMessage(), e);
        }
    }

    private CompletableFuture<JsonNode> callAsync(String method, Object... params) {
        return CompletableFuture.supplyAsync(() -> call(method, params));
    }

    // Parsing helpers

    private BigInteger hexToBigInteger(String hex) {
        String clean = hex.startsWith("0x") ? hex.substring(2) : hex;
        return clean.isEmpty() ? BigInteger.ZERO : new BigInteger(clean, 16);
    }

    private Optional<Block> parseBlock(JsonNode node) {
        if (node == null || node.isNull()) {
            return Optional.empty();
        }

        List<Hash> txHashes = new ArrayList<>();
        JsonNode txs = node.get("transactions");
        if (txs != null && txs.isArray()) {
            for (JsonNode tx : txs) {
                txHashes.add(Hash.fromHex(tx.asText()));
            }
        }

        return Optional.of(new Block(
            hexToBigInteger(node.get("number").asText()),
            Hash.fromHex(node.get("hash").asText()),
            Hash.fromHex(node.get("parentHash").asText()),
            hexToBigInteger(node.get("timestamp").asText()),
            txHashes,
            hexToBigInteger(node.get("gasLimit").asText()),
            hexToBigInteger(node.get("gasUsed").asText()),
            Address.fromHex(node.get("miner").asText())
        ));
    }

    private Optional<TransactionRequest> parseTransaction(JsonNode node) {
        if (node == null || node.isNull()) {
            return Optional.empty();
        }
        // Simplified - return empty for now
        return Optional.empty();
    }

    private Optional<TransactionReceipt> parseReceipt(JsonNode node) {
        if (node == null || node.isNull()) {
            return Optional.empty();
        }

        List<Log> logs = new ArrayList<>();
        JsonNode logsNode = node.get("logs");
        if (logsNode != null && logsNode.isArray()) {
            for (JsonNode logNode : logsNode) {
                List<Hash> topics = new ArrayList<>();
                JsonNode topicsNode = logNode.get("topics");
                if (topicsNode != null && topicsNode.isArray()) {
                    for (JsonNode topic : topicsNode) {
                        topics.add(Hash.fromHex(topic.asText()));
                    }
                }

                logs.add(new Log(
                    Address.fromHex(logNode.get("address").asText()),
                    topics,
                    Hex.toBytes(logNode.get("data").asText()),
                    hexToBigInteger(logNode.get("blockNumber").asText()),
                    Hash.fromHex(logNode.get("transactionHash").asText()),
                    hexToBigInteger(logNode.get("transactionIndex").asText()),
                    Hash.fromHex(logNode.get("blockHash").asText()),
                    hexToBigInteger(logNode.get("logIndex").asText())
                ));
            }
        }

        String toHex = node.has("to") && !node.get("to").isNull() ? node.get("to").asText() : null;
        String contractHex = node.has("contractAddress") && !node.get("contractAddress").isNull()
            ? node.get("contractAddress").asText() : null;

        return Optional.of(new TransactionReceipt(
            Hash.fromHex(node.get("transactionHash").asText()),
            Hash.fromHex(node.get("blockHash").asText()),
            hexToBigInteger(node.get("blockNumber").asText()),
            hexToBigInteger(node.get("transactionIndex").asText()),
            Address.fromHex(node.get("from").asText()),
            toHex != null ? Address.fromHex(toHex) : null,
            hexToBigInteger(node.get("gasUsed").asText()),
            hexToBigInteger(node.get("cumulativeGasUsed").asText()),
            contractHex != null ? Address.fromHex(contractHex) : null,
            logs,
            hexToBigInteger(node.get("status").asText())
        ));
    }
}
