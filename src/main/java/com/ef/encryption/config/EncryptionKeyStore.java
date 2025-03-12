package com.ef.encryption.config;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * EncryptionKeyStore provides a secure mechanism for storing and retrieving encryption keys
 * with basic obfuscation using an XOR mask.
 */
public class EncryptionKeyStore {

    private EncryptionKeyStore() {}

    // Static storage for obfuscated keys
    private static final ConcurrentHashMap<String, byte[]> obfuscatedKeys = new ConcurrentHashMap<>();

    // Static XOR mask for obfuscation
    private static final byte[] xorMask;

    // Static block to initialize the XOR mask securely
    static {
        xorMask = generateXorMask(16); // Use a 16-byte secure random mask
    }

    /**
     * Generates a secure random XOR mask.
     *
     * @param length The length of the mask in bytes.
     * @return A randomly generated XOR mask.
     */
    private static byte[] generateXorMask(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] mask = new byte[length];
        secureRandom.nextBytes(mask);
        return mask;
    }

    /**
     * Stores an encryption key in an obfuscated format.
     *
     * @param keyName   The name of the key.
     * @param secretKey The secret key to store.
     * @throws IllegalArgumentException If keyName or secretKey is null.
     */
    public static void storeKey(String keyName, SecretKey secretKey) {
        if (keyName == null || secretKey == null) {
            throw new IllegalArgumentException("Key name and key bytes cannot be null");
        }

        byte[] keyBytes = secretKey.getEncoded();
        obfuscatedKeys.put(keyName, applyXorMask(keyBytes));
    }

    /**
     * Retrieves an encryption key by its version.
     *
     * @param version The version of the key to retrieve ("latest" for the most recent key).
     * @return A map containing the key version and the retrieved SecretKey.
     * @throws RuntimeException If the requested key is not found.
     */
    public static Map<String, SecretKey> retrieveKey(String version) {
        byte[] obfuscated = null;

        if (version.equalsIgnoreCase("latest") || version.isEmpty()) {
            Map.Entry<String, byte[]> e = Collections.max(obfuscatedKeys.entrySet(), Map.Entry.comparingByKey());
            obfuscated = e.getValue();
            version = e.getKey();
        } else {
            obfuscated = obfuscatedKeys.get(version);
        }

        if (obfuscated == null) {
            throw new RuntimeException("Key not found: " + version);
        }

        byte[] keyBytes = applyXorMask(obfuscated); // De-obfuscate
        HashMap<String, SecretKey> secretKeyHashMap = new HashMap<>();
        secretKeyHashMap.put(version, new SecretKeySpec(keyBytes, "AES"));
        return secretKeyHashMap;
    }

    /**
     * Clears all stored keys securely.
     */
    public static void clearKeys() {
        obfuscatedKeys.clear();
    }

    /**
     * Applies XOR masking to obfuscate or de-obfuscate data.
     *
     * @param data The input data to apply the XOR mask.
     * @return The masked/unmasked data.
     */
    private static byte[] applyXorMask(byte[] data) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ xorMask[i % xorMask.length]);
        }
        return result;
    }

    /**
     * Clears sensitive data from memory by overwriting it.
     *
     * @param data The data to be cleared.
     */
    public static void clearSensitiveData(byte[] data) {
        if (data != null) {
            java.util.Arrays.fill(data, (byte) 0);
        }
    }

    /**
     * Checks whether a key exists in storage.
     *
     * @param key The key name or version to check.
     * @return True if the key exists, false otherwise.
     */
    public static boolean hasKey(String key) {
        if (key == null || obfuscatedKeys.isEmpty()) {
            return false;
        }
        // If "latest" or an empty string is requested, we consider it present if the store is non-empty.
        if (key.equalsIgnoreCase("latest") || key.isEmpty()) {
            return true;
        }
        return obfuscatedKeys.containsKey(key);
    }
}