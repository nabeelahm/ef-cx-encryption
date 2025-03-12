package com.ef.encryption.controller;

import com.ef.encryption.bootstrap.Bootstrap;
import com.ef.encryption.config.EncryptionKeyStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for managing encryption keys.
 */
@RestController
public class EncryptionController {

    private final Bootstrap bootstrap;

    public EncryptionController(Bootstrap bootstrap) {
        this.bootstrap = bootstrap;
    }

    /**
     * Reloads encryption keys in memory.
     */
    @GetMapping("/reload-keys")
    public void reloadEncryptionKeys() {
        EncryptionKeyStore.clearKeys();
        bootstrap.loadEncryptionKeys();

    }
}
