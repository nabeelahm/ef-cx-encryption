package com.ef.encryption.config;

import ch.qos.logback.core.util.StringUtil;
import com.ef.encryption.utils.CryptoUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.RawTransitKey;
import org.springframework.vault.support.TransitKeyType;
import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Map;

/**
 * Service for handling encryption and decryption using Vault's Transit Secrets Engine.
 */
@Slf4j
@Service
public class VaultTransit {
    private final VaultOperations vault;
    private final String path;
    private final String key;
    private final CryptoUtil cryptoUtil;

    /**
     * Constructs a VaultTransit instance.
     *
     * @param properties     Vault transit properties.
     * @param vaultTemplate  Vault template for interacting with Vault.
     * @param cryptoUtil     Crypto utility for encryption and decryption.
     */
    public VaultTransit(VaultTransitProperties properties, VaultTemplate vaultTemplate, CryptoUtil cryptoUtil) {
        this.vault = vaultTemplate;
        this.path = properties.getPath();
        this.key = properties.getKey();
        this.cryptoUtil = cryptoUtil;
    }

    /**
     * Decrypts the given ciphertext.
     *
     * @param ciphertext The encrypted data.
     * @return The decrypted plaintext.
     */
    public String decrypt(String ciphertext) {
        if (StringUtil.isNullOrEmpty(ciphertext)) {
            return ciphertext;
        }

        String decryptedString = ciphertext;
        String[] encodedString = ciphertext.split(":");
        String version = Character.toString(encodedString[1].charAt(1));
        if (EncryptionKeyStore.hasKey(version)) {
            try {
                decryptedString = cryptoUtil.decrypt(
                        encodedString[2],
                        EncryptionKeyStore.retrieveKey(version).values().iterator().next());
            } catch (Exception e) {
                log.error("Decryption failed: {}", e.getMessage());
            }
        } else {
            SecretKey secretKey = cryptoUtil.getKeyFromVault(this.exportKey(version).split(":")[1]);
            try {
                decryptedString = cryptoUtil.decrypt(encodedString[2], secretKey);
                EncryptionKeyStore.storeKey(version, secretKey);
            } catch (Exception e) {
                log.error("Decryption failed: {}", e.getMessage());
            }
        }
        return decryptedString;
    }

    /**
     * Encrypts the given plaintext.
     *
     * @param plaintext The data to encrypt.
     * @return The encrypted string.
     */
    public String encrypt(String plaintext) {
        if (StringUtil.isNullOrEmpty(plaintext)) {
            return plaintext;
        }

        String version = "latest";
        String keyVersion;
        SecretKey secretKey;

        if (EncryptionKeyStore.hasKey(version)) {
            keyVersion = EncryptionKeyStore.retrieveKey(version).keySet().iterator().next();
            secretKey = EncryptionKeyStore.retrieveKey(version).values().iterator().next();
        } else {
            String[] keyString = this.exportKey(version).split(":");
            keyVersion = keyString[0];
            String encryptionKey = keyString[1];
            secretKey = cryptoUtil.getKeyFromVault(encryptionKey);
        }

        EncryptionKeyStore.storeKey(keyVersion, secretKey);
        String encrypted = plaintext;

        try {
            encrypted = cryptoUtil.encrypt(plaintext, secretKey);
            return "vault:v" + keyVersion + ":" + encrypted;
        } catch (Exception e) {
            log.error("Encryption failed: {}", e.getMessage());
        }

        return encrypted;
    }

    /**
     * Exports the encryption key from Vault.
     *
     * @param version The key version to export. Use "latest" for the most recent version.
     * @return The exported key.
     */
    public String exportKey(String version) {
        RawTransitKey key1 = vault.opsForTransit(path).exportKey(key, TransitKeyType.ENCRYPTION_KEY);
        if (key1 == null) {
            throw new RuntimeException("Could not find vault transit key");
        }

        if (version.equalsIgnoreCase("latest") || version.isEmpty()) {
            Map.Entry<String, String> e = Collections.max(key1.getKeys().entrySet(), Map.Entry.comparingByKey());
            return e.getKey() + ":" + e.getValue();
        }

        return version + ":" + key1.getKeys().get(version);
    }

    /**
     * Exports all versions of the encryption key from Vault.
     *
     * @return The exported keys.
     */
    public Map<String, String> exportAllKeys() {
        RawTransitKey key1 = vault.opsForTransit(path).exportKey(key, TransitKeyType.ENCRYPTION_KEY);
        if (key1 == null) {
            throw new RuntimeException("Could not find vault transit key");
        }

        return key1.getKeys();
    }
}
