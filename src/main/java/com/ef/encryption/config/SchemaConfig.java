package com.ef.encryption.config;

import com.ef.encryption.model.CollectionEncryptionSchema;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;


/**
 * Service to load Encryption Schema in memory at startup.
 */
@Service
public class SchemaConfig {

    @Value("${transit.encryption-schema}")
    private Resource schemaResource;

    // A map where the key is the collection name (e.g., "users")
    // and the value is the schema for that collection.
    private Map<String, CollectionEncryptionSchema> encryptionSchemas = Collections.emptyMap();

    /**
     * Loads the encryption schema from the file.
     */
    @PostConstruct
    public void loadSchema() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            encryptionSchemas = mapper.readValue(
                    schemaResource.getInputStream(),
                    new TypeReference<Map<String, CollectionEncryptionSchema>>() {}
            );
        } catch (IOException e) {
            throw new RuntimeException("Failed to load encryption schema", e);
        }
    }

    /**
     * Returns the encryption schema for the given collection.
     */
    public CollectionEncryptionSchema getSchemaForCollection(String collectionName) {
        return encryptionSchemas.get(collectionName);
    }

    /**
     * Convenience method to get the list of fields to encrypt.
     * (May return null if not defined.)
     */
    public List<String> getEncryptableFields(String collectionName) {
        CollectionEncryptionSchema schema = encryptionSchemas.get(collectionName);
        return (schema != null && schema.getEncrypt() != null) ? schema.getEncrypt() : Collections.emptyList();
    }
}
