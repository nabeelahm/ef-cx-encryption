package com.ef.encryption.bootstrap;

import com.ef.encryption.config.EncryptionKeyStore;
import com.ef.encryption.config.VaultTransit;
import com.ef.encryption.utils.CryptoUtil;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Bootstrap class to run at startup of the application.
 */
@Slf4j
@Service
public class Bootstrap {

    private final VaultTransit vaultTransit;
    private final CryptoUtil cryptoUtil;
    private final boolean enableEncryption;

    Bootstrap(VaultTransit vaultTransit, CryptoUtil cryptoUtil,
              @Value("${ef.enable-encryption}") boolean enableEncryption) {
        this.vaultTransit = vaultTransit;
        this.cryptoUtil = cryptoUtil;
        this.enableEncryption = enableEncryption;
    }

    /**
     * Loads encryption keys from the vault in the local cache.
     */
    @PostConstruct
    public void loadEncryptionKeys() {
        if (!enableEncryption) {
            return;
        }
        log.debug("Loading encryption keys");
        vaultTransit.exportAllKeys().forEach((key, value) -> EncryptionKeyStore.storeKey(key,
                cryptoUtil.getKeyFromVault(value)));
        log.debug("Finished loading encryption keys");
    }
}
