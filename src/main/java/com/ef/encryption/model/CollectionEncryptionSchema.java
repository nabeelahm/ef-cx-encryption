package com.ef.encryption.model;

import lombok.Data;
import java.util.List;
import java.util.Map;

/**
 * Schema for a collection's encryption settings, including fields to encrypt, skipIf, and notSkipIf rules.
 */
@Data
public class CollectionEncryptionSchema {
    private List<String> encrypt;
    private Map<String, List<String>> skipIf;
    private Map<String, List<String>> notSkipIf;
}
