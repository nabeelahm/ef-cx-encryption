package com.ef.encryption.config;

import com.ef.encryption.model.CollectionEncryptionSchema;
import lombok.extern.slf4j.Slf4j;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.mapping.event.AfterConvertCallback;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertCallback;
import org.springframework.stereotype.Component;
import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Intercepts entity conversion for encryption and decryption.
 * Uses field paths and global skip/process rules from the schema (supports nested fields).
 */
@Slf4j
@Component
public class EncryptionInterceptor implements BeforeConvertCallback<Object>, AfterConvertCallback<Object> {

    private final SchemaConfig schemaService;
    private final VaultTransit vaultEncryptionService;
    private final boolean enableEncryption;

    private static final ConcurrentMap<Class<?>, Map<String, Field>> fieldCache = new ConcurrentHashMap<>();

    EncryptionInterceptor(SchemaConfig schemaService, VaultTransit vaultEncryptionService,
                          @Value("${ef.enable-encryption}") boolean enableEncryption) {
        this.schemaService = schemaService;
        this.vaultEncryptionService = vaultEncryptionService;
        this.enableEncryption = enableEncryption;
    }

    @Override
    public Object onBeforeConvert(Object entity, String collection) {
        if (!enableEncryption) {
            return entity;
        }
        List<String> fieldPaths = schemaService.getEncryptableFields(collection);
        if(fieldPaths.isEmpty()) {
            return entity;
        }

        log.info("Starting encryption processing for collection '{}'.", collection);
        log.debug("Encryption field paths: {}", fieldPaths);
        for (String path : fieldPaths) {
            try {
                log.debug("Processing encryption for field path: {}", path);
                processFieldPath(entity, path, collection, true);
            } catch (Exception e) {
                log.error("Error processing encryption for path '{}'.", path, e);
                throw new RuntimeException(e);
            }
        }
        log.info("Completed encryption processing for collection '{}'.", collection);
        return entity;
    }

    @Override
    public Object onAfterConvert(Object entity, Document document, String collection) {
        if (!enableEncryption) {
            return entity;
        }
        List<String> fieldPaths = schemaService.getEncryptableFields(collection);
        if(fieldPaths.isEmpty()) {
            return entity;
        }

        log.info("Starting decryption processing for collection '{}'.", collection);
        log.debug("Decryption field paths: {}", fieldPaths);
        for (String path : fieldPaths) {
            try {
                log.debug("Processing decryption for field path: {}", path);
                processFieldPath(entity, path, collection, false);
            } catch (Exception e) {
                log.error("Error processing decryption for path '{}'.", path, e);
                throw new RuntimeException(e);
            }
        }
        log.info("Completed decryption processing for collection '{}'.", collection);
        return entity;
    }

    private void processFieldPath(Object entity, String path, String collection, boolean isEncryption)
            throws Exception {
        log.debug("Processing field path '{}' for {} in collection '{}'.", path,
                isEncryption ? "encryption" : "decryption", collection);
        if (shouldSkipDocument(collection, entity)) {
            log.info("Global conditions triggered; skipping {} for collection '{}'.",
                    isEncryption ? "encryption" : "decryption", collection);
            return;
        }
        String[] parts = path.split("\\.");
        log.debug("Split field path into {} parts.", parts.length);
        processRecursive(entity, parts, 0, collection, isEncryption);
    }

    private void processRecursive(Object obj, String[] parts, int index, String collection, boolean isEncryption)
            throws Exception {
        if (obj == null || index >= parts.length) {
            return;
        }
        String key = parts[index];
        log.debug("Recursion level {}: processing key '{}'.", index, key);
        if (obj instanceof Map) {
            processMap((Map<?, ?>) obj, parts, index, collection, isEncryption);
        } else {
            processPojo(obj, parts, index, collection, isEncryption);
        }
    }

    @SuppressWarnings("unchecked")
    private void processMap(Map<?, ?> rawMap, String[] parts, int index, String collection, boolean isEncryption)
            throws Exception {
        Map<Object, Object> map = (Map<Object, Object>) rawMap;
        if (!map.containsKey(parts[index])) {
            log.debug("Key '{}' not found in map.", parts[index]);
            return;
        }
        Object value = map.get(parts[index]);
        if (value == null) {
            return;
        }
        if (index == parts.length - 1) {
            log.debug("Processing leaf node for map key '{}'.", parts[index]);
            processLeafForMap(map, parts[index], value, isEncryption);
        } else {
            if (value instanceof List<?> list) {
                for (Object item : list) {
                    processRecursive(item, parts, index + 1, collection, isEncryption);
                }
            } else {
                processRecursive(value, parts, index + 1, collection, isEncryption);
            }
        }
    }

    private void processPojo(Object obj, String[] parts, int index, String collection, boolean isEncryption)
            throws Exception {
        Field field = getField(obj.getClass(), parts[index]);
        if (field == null) {
            log.debug("Field '{}' not found in class {}.", parts[index], obj.getClass().getName());
            return;
        }
        field.setAccessible(true);
        Object fieldValue = field.get(obj);
        if (fieldValue == null) {
            return;
        }
        if (index == parts.length - 1) {
            log.debug("Processing leaf node for POJO field '{}'.", parts[index]);
            processLeafForPojo(obj, field, parts[index], fieldValue, isEncryption);
        } else {
            if (fieldValue instanceof List<?> list) {
                for (Object item : list) {
                    processRecursive(item, parts, index + 1, collection, isEncryption);
                }
            } else {
                processRecursive(fieldValue, parts, index + 1, collection, isEncryption);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void processLeafForMap(Map<Object, Object> map, String key, Object value, boolean isEncryption) {

        if (value instanceof List<?> list) {
            processListLeaf(key, (List<Object>) list, isEncryption);
        } else {
            Object processed = processLeafValue(value, isEncryption, value.getClass());
            log.debug("{} map field '{}' (leaf node) processed.", isEncryption ? "Encrypting" : "Decrypting", key);
            map.put(key, Objects.requireNonNullElse(processed, ""));
        }
    }

    private void processLeafForPojo(Object obj, Field field, String key, Object value, boolean isEncryption)
            throws Exception {

        if (value instanceof List<?> list) {
            processListLeaf(key, (List<Object>) list, isEncryption);
        } else {
            Object processed = processLeafValue(value, isEncryption, value.getClass());
            log.debug("{} POJO field '{}' (leaf node) processed.", isEncryption ? "Encrypting" : "Decrypting", key);
            field.set(obj, Objects.requireNonNullElse(processed, ""));
        }
    }

    @SuppressWarnings("unchecked")
    private void processListLeaf(String key, List<Object> list, boolean isEncryption) {
        for (int i = 0; i < list.size(); i++) {
            Object item = list.get(i);
            if (item == null) {
                continue;
            }
            Object processed = processLeafValue(item, isEncryption, item.getClass());
            log.debug("{} list item for key '{}' at index {} processed.",
                    isEncryption ? "Encrypting" : "Decrypting", key, i);
            list.set(i, Objects.requireNonNullElse(processed, ""));
        }
    }

    private Object processLeafValue(Object value, boolean isEncryption, Class<?> targetType) {
        try {
            if (value == null) {
                return null;
            }

            if (value instanceof String s) {
                return processString(s, isEncryption);
            }

            if (value instanceof Number || value instanceof Boolean || value instanceof Character) {
                return isEncryption ? vaultEncryptionService.encrypt(convertToString(value)) : value;
            }

            // Skip recursion for unrecognized types, return them as-is
            if (shouldSkipProcessing(targetType)) {
                return value;
            }

            // Recursively process only known complex types
            recursivelyProcessObject(value, isEncryption, new HashSet<>());
            return value;
        } catch (Exception e) {
            log.warn("Skipping encryption/decryption for unrecognized type: {}. Error: {}", targetType, e.getMessage());
            return value; // Return original value instead of failing
        }
    }

    private boolean shouldSkipProcessing(Class<?> targetType) {
        // Allow collections and maps to be processed
        if (Collection.class.isAssignableFrom(targetType) || Map.class.isAssignableFrom(targetType)) {
            return false;
        }

        // Skip primitive types, wrapper types, and standard Java library classes
        return targetType.getName().startsWith("java.") || targetType.getName().startsWith("javax.");
    }

    private void recursivelyProcessObject(Object obj, boolean isEncryption, Set<Object> visitedObjects) {
        if (obj == null || obj instanceof String || visitedObjects.contains(obj)) {
            return;
        }
        visitedObjects.add(obj);

        if (obj instanceof Map<?, ?>) {
            processMapObject((Map<?, ?>) obj, isEncryption, visitedObjects);
        } else if (obj instanceof List<?>) {
            processListObject((List<?>) obj, isEncryption, visitedObjects);
        } else {
            processPojoObject(obj, isEncryption, visitedObjects);
        }
    }

    @SuppressWarnings("unchecked")
    private void processMapObject(Map<?, ?> map, boolean isEncryption, Set<Object> visitedObjects) {
        Map<Object, Object> objMap = (Map<Object, Object>) map;
        for (Map.Entry<Object, Object> entry : objMap.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof String item) {
                entry.setValue(processString(item, isEncryption));
                log.debug("Processed Map key '{}' value.", entry.getKey());
            } else {
                recursivelyProcessObject(value, isEncryption, visitedObjects);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void processListObject(List<?> list, boolean isEncryption, Set<Object> visitedObjects) {
        List<Object> objList = (List<Object>) list;
        for (int i = 0; i < list.size(); i++) {
            Object item = list.get(i);
            if (item instanceof String value) {
                objList.set(i, processString(value, isEncryption));
                log.debug("Processed List item at index {}.", i);
            } else {
                recursivelyProcessObject(item, isEncryption, visitedObjects);
            }
        }
    }

    private void processPojoObject(Object obj, boolean isEncryption, Set<Object> visitedObjects) {
        if (obj.getClass().getName().startsWith("java.lang.") || obj instanceof Timestamp) {
            return;
        }

        Field[] fields = obj.getClass().getDeclaredFields();
        for (Field field : fields) {
            try {
                field.setAccessible(true);
                Object value = field.get(obj);
                if (value instanceof String) {
                    field.set(obj, processString((String) value, isEncryption));
                } else {
                    recursivelyProcessObject(value, isEncryption, visitedObjects);
                }
            } catch (Exception e) {
                log.error("Error processing field '{}' in class {}.", field.getName(), obj.getClass().getName(), e);
            }
        }
    }

    private Object processString(String s, boolean isEncryption) {
        if (isEncryption) {
            return s.startsWith("vault:") ? s : vaultEncryptionService.encrypt(convertToString(s));
        } else {
            return s.startsWith("vault:") ? convertFromString(vaultEncryptionService.decrypt(s)) : s;
        }
    }

    private String convertToString(Object value) {
        if (value == null) {
            return "";
        }

        String stringValue = value.toString();
        return stringValue.isEmpty() ? "" : value.getClass().getName() + ":" + stringValue;
    }


    private Object convertFromString(String value) {
        if (value.isEmpty()) {
            return value;
        }

        String className = value.split(":")[0];
        String actualValue = value.split(":")[1];
        return switch (className) {
            case "java.lang.Integer", "int" -> Integer.parseInt(actualValue);
            case "java.lang.Long", "long" -> Long.parseLong(actualValue);
            case "java.lang.Double", "double" -> Double.parseDouble(actualValue);
            case "java.lang.Boolean", "boolean" -> Boolean.parseBoolean(actualValue);
            case "java.lang.Character", "char" -> actualValue.charAt(0);
            case "java.lang.String", "string" -> actualValue;
            default -> throw new IllegalArgumentException("Unsupported wrapper class: " + className);
        };
    }

    private boolean shouldSkipDocument(String collectionName, Object document) {
        CollectionEncryptionSchema schema = schemaService.getSchemaForCollection(collectionName);
        if (schema == null) {
            return false;
        }
        if (schema.getNotSkipIf() != null) {
            boolean failsNotSkip = schema.getNotSkipIf().entrySet().stream()
                    .anyMatch(entry -> {
                        Object fieldValue = getNestedFieldValue(document, entry.getKey());
                        boolean fails = fieldValue == null || !entry.getValue().contains(fieldValue.toString());
                        if (fails) {
                            log.debug("Document fails notSkipIf rule for '{}'.", entry.getKey());
                        }
                        return fails;
                    });
            if (failsNotSkip) {
                return true;
            }
        }
        if (schema.getSkipIf() != null) {
            return schema.getSkipIf().entrySet().stream()
                    .anyMatch(entry -> {
                        Object fieldValue = getNestedFieldValue(document, entry.getKey());
                        boolean trigger = fieldValue != null && entry.getValue().contains(fieldValue.toString());
                        if (trigger) {
                            log.debug("Document matches skipIf rule for '{}'.", entry.getKey());
                        }
                        return trigger;
                    });
        }
        return false;
    }

    private Object getNestedFieldValue(Object document, String keyPath) {
        if (document == null || keyPath == null || keyPath.isEmpty()) {
            return null;
        }
        String[] keys = keyPath.split("\\.");
        Object current = document;
        for (String key : keys) {
            if (current == null) {
                return null;
            }
            if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(key);
            } else {
                try {
                    Field field = getField(current.getClass(), key);
                    current = field.get(current);
                } catch (Exception e) {
                    return null;
                }
            }
        }
        return current;
    }

    private Field getField(Class<?> clazz, String fieldName) {
        Map<String, Field> classFieldMap = fieldCache.computeIfAbsent(clazz, k -> new ConcurrentHashMap<>());
        return classFieldMap.computeIfAbsent(fieldName, fn -> {
            try {
                Field f = clazz.getDeclaredField(fn);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException e) {
                Class<?> superClazz = clazz.getSuperclass();
                return (superClazz != null) ? getField(superClazz, fn) : null;
            }
        });
    }
}