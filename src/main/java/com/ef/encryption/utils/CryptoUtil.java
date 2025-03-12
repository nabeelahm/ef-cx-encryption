package com.ef.encryption.utils;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for encrypting and decrypting data using AES-256-GCM with optional deterministic IV generation.
 */
@Component
public class CryptoUtil {
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final boolean DETERMINISTIC = false;

    /**
     * Converts a Base64-encoded key retrieved from Vault into a usable SecretKey.
     *
     * @param base64Key the Base64-encoded AES key.
     * @return the SecretKey derived from the Base64 key.
     */
    public SecretKey getKeyFromVault(String base64Key) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decodedKey, "AES");
    }

    /**
     * Encrypts data using AES-256-GCM with optional compression.
     *
     * @param data the plaintext data to encrypt.
     * @param key  the AES secret key.
     * @return the encrypted data as a Base64-encoded string.
     * @throws Exception if encryption fails.
     */
    public String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] compressedData = CompressionUtil.compress(data.getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[GCM_IV_LENGTH];

        if (!DETERMINISTIC) {
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
        } else {
            iv = generateDeterministicIv(data);
        }

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] encryptedData = cipher.doFinal(compressedData);
        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypts data using AES-256-GCM with optional decompression.
     *
     * @param encryptedData the Base64-encoded encrypted data.
     * @param key           the AES secret key.
     * @return the decrypted plaintext data.
     * @throws Exception if decryption fails.
     */
    public String decrypt(String encryptedData, SecretKey key) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);

        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(decodedData, 0, iv, 0, GCM_IV_LENGTH);

        byte[] ciphertext = new byte[decodedData.length - GCM_IV_LENGTH];
        System.arraycopy(decodedData, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        byte[] decryptedData = cipher.doFinal(ciphertext);
        byte[] decompressedData = CompressionUtil.decompress(decryptedData);

        return new String(decompressedData);
    }

    /**
     * Generates a deterministic IV based on the plaintext using SHA-256.
     *
     * @param plaintext the input text for which an IV is generated.
     * @return a 12-byte IV derived from the hash of the plaintext.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    private static byte[] generateDeterministicIv(String plaintext) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(hash, 0, iv, 0, GCM_IV_LENGTH);
        return iv;
    }
}