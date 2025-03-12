package com.ef.encryption.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for Vault Transit.
 */
@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "transit")
public class VaultTransitProperties {
    /**
     * The Vault transit path.
     */
    private String path;

    /**
     * The key name used in Vault Transit.
     */
    private String key;
}