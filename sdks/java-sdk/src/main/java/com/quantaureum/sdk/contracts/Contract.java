// Quantaureum Java SDK source, version 1.0.0.
package com.quantaureum.sdk.contracts;

import com.quantaureum.sdk.accounts.Account;
import com.quantaureum.sdk.client.CallRequest;
import com.quantaureum.sdk.client.QuantaureumClient;
import com.quantaureum.sdk.exceptions.AbiException;
import com.quantaureum.sdk.exceptions.RpcException;
import com.quantaureum.sdk.exceptions.TransactionException;
import com.quantaureum.sdk.types.Address;
import com.quantaureum.sdk.types.Hash;
import com.quantaureum.sdk.types.TransactionReceipt;
import com.quantaureum.sdk.types.TransactionRequest;
import com.quantaureum.sdk.utils.Hex;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;

/**
 * Smart contract wrapper for interacting with deployed contracts.
 * Provides methods for calling view functions and sending transactions.
 */
public class Contract {
    private final QuantaureumClient client;
    private final Address address;
    private final Abi abi;
    private Account signer;
    private BigInteger gasLimit;
    private BigInteger gasPrice;

    /**
     * Create a contract instance.
     *
     * @param client  The Quantaureum client
     * @param address The contract address
     * @param abi     The contract ABI
     */
    public Contract(QuantaureumClient client, Address address, Abi abi) {
        this.client = client;
        this.address = address;
        this.abi = abi;
    }

    /**
     * Create a contract instance from address string.
     */
    public Contract(QuantaureumClient client, String address, Abi abi) {
        this(client, Address.fromHex(address), abi);
    }

    /**
     * Create a contract instance from ABI JSON.
     */
    public static Contract fromJson(QuantaureumClient client, String address, String abiJson) throws AbiException {
        return new Contract(client, Address.fromHex(address), Abi.fromJson(abiJson));
    }

    /**
     * Set the signer account for transactions.
     */
    public Contract connect(Account signer) {
        this.signer = signer;
        return this;
    }

    /**
     * Set default gas limit for transactions.
     */
    public Contract setGasLimit(BigInteger gasLimit) {
        this.gasLimit = gasLimit;
        return this;
    }

    /**
     * Set default gas price for transactions.
     */
    public Contract setGasPrice(BigInteger gasPrice) {
        this.gasPrice = gasPrice;
        return this;
    }

    /**
     * Call a view/pure function (read-only, no transaction).
     *
     * @param functionName The function name
     * @param args         The function arguments
     * @return The decoded return values
     */
    public Object[] call(String functionName, Object... args) throws RpcException, AbiException {
        Abi.AbiFunction fn = abi.getFunction(functionName);
        if (fn == null) {
            throw new AbiException("Function not found: " + functionName);
        }

        String data = abi.encodeFunctionHex(functionName, args);

        CallRequest callRequest = new CallRequest.Builder()
                .to(address)
                .data(data)
                .build();

        byte[] result = client.call(callRequest);

        if (result == null || result.length == 0) {
            return new Object[0];
        }

        return abi.decodeReturn(functionName, result);
    }

    /**
     * Call a view/pure function asynchronously.
     */
    public CompletableFuture<Object[]> callAsync(String functionName, Object... args) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return call(functionName, args);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }


    /**
     * Send a transaction to a state-changing function.
     *
     * @param functionName The function name
     * @param args         The function arguments
     * @return A PendingTransaction that can be awaited
     */
    public PendingTransaction send(String functionName, Object... args) throws RpcException, AbiException, TransactionException {
        return send(functionName, BigInteger.ZERO, args);
    }

    /**
     * Send a transaction with value to a payable function.
     *
     * @param functionName The function name
     * @param value        The value to send in wei
     * @param args         The function arguments
     * @return A PendingTransaction that can be awaited
     */
    public PendingTransaction send(String functionName, BigInteger value, Object... args)
            throws RpcException, AbiException, TransactionException {
        if (signer == null) {
            throw new TransactionException("No signer connected. Call connect(account) first.");
        }

        Abi.AbiFunction fn = abi.getFunction(functionName);
        if (fn == null) {
            throw new AbiException("Function not found: " + functionName);
        }

        String data = abi.encodeFunctionHex(functionName, args);

        // Get nonce
        BigInteger nonce = client.getNonce(signer.getAddress());

        // Get gas price if not set
        BigInteger txGasPrice = this.gasPrice;
        if (txGasPrice == null) {
            txGasPrice = client.getGasPrice();
        }

        // Estimate gas if not set
        BigInteger txGasLimit = this.gasLimit;
        if (txGasLimit == null) {
            CallRequest estimateRequest = new CallRequest.Builder()
                    .from(signer.getAddress().toHex())
                    .to(address.toHex())
                    .data(data)
                    .value(value)
                    .build();
            txGasLimit = client.estimateGas(estimateRequest);
            // Add 20% buffer
            txGasLimit = txGasLimit.multiply(BigInteger.valueOf(120)).divide(BigInteger.valueOf(100));
        }

        // Build transaction
        TransactionRequest tx = new TransactionRequest.Builder()
                .to(address)
                .value(value)
                .nonce(nonce)
                .gasPrice(txGasPrice)
                .gasLimit(txGasLimit)
                .data(Hex.toBytes(data))
                .build();

        // Sign and send
        var signedTx = signer.signTransaction(tx, client.getChainId());
        Hash txHash = client.sendTransaction(signedTx);

        return new PendingTransaction(client, txHash);
    }

    /**
     * Send a transaction asynchronously.
     */
    public CompletableFuture<PendingTransaction> sendAsync(String functionName, Object... args) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return send(functionName, args);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Encode function call data without sending.
     */
    public String encodeFunction(String functionName, Object... args) throws AbiException {
        return abi.encodeFunctionHex(functionName, args);
    }

    /**
     * Decode function return data.
     */
    public Object[] decodeReturn(String functionName, String data) throws AbiException {
        return abi.decodeReturnHex(functionName, data);
    }

    /**
     * Get the contract address.
     */
    public Address getAddress() {
        return address;
    }

    /**
     * Get the contract ABI.
     */
    public Abi getAbi() {
        return abi;
    }

    /**
     * Get the connected signer.
     */
    public Account getSigner() {
        return signer;
    }

    /**
     * Create an event filter for this contract.
     */
    public EventFilter events(String eventName) throws AbiException {
        Abi.AbiEvent event = abi.getEvent(eventName);
        if (event == null) {
            throw new AbiException("Event not found: " + eventName);
        }
        return new EventFilter(client, address, event);
    }
}
