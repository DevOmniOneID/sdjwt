package com.example.oid4vc.sdjwt.core;

import com.example.oid4vc.sdjwt.exception.InvalidDisclosureException;
import com.example.oid4vc.sdjwt.exception.SDJWTParseException;
import com.example.oid4vc.sdjwt.util.Base64UrlUtils;
import com.example.oid4vc.sdjwt.util.HashUtils;
import com.example.oid4vc.sdjwt.util.SaltGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Disclosure represents a basic component in the SD-JWT specification.
 * A Disclosure consists of a salt, a claim name and a claim value (for an object property),
 * or consists of a salt and a claim value (for an array element).
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class Disclosure {
    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    private final String salt;
    private final String claimName; // null for array elements
    private final Object claimValue;
    
    /**
     * Constructor for object property disclosure.
     * 
     * @param salt      the salt value (base64url-encoded string with 128-bit or higher entropy)
     * @param claimName the claim name
     * @param claimValue the claim value
     * @throws InvalidDisclosureException if parameters are invalid
     */
    public Disclosure(String salt, String claimName, Object claimValue) {
        if (salt == null || salt.trim().isEmpty()) {
            throw new InvalidDisclosureException("Salt cannot be null or empty");
        }
        if (claimName == null || claimName.trim().isEmpty()) {
            throw new InvalidDisclosureException("Claim name cannot be null or empty for object property");
        }
        
        this.salt = salt;
        this.claimName = claimName;
        this.claimValue = claimValue;
    }
    
    /**
     * Constructor for array element disclosure with auto-generated salt.
     * 
     * @param claimValue the claim value (array element)
     */
    public Disclosure(Object claimValue) {
        this.salt = SaltGenerator.generate();
        this.claimName = null; // null for array elements
        this.claimValue = claimValue;
    }
    
    /**
     * Constructor for array element disclosure with explicit salt.
     * 
     * @param salt the salt value
     * @param claimValue the claim value (array element)
     * @throws InvalidDisclosureException if salt is invalid
     */
    public Disclosure(String salt, Object claimValue) {
        if (salt == null || salt.trim().isEmpty()) {
            throw new InvalidDisclosureException("Salt cannot be null or empty");
        }
        
        this.salt = salt;
        this.claimName = null; // null for array elements
        this.claimValue = claimValue;
    }
    
    /**
     * Create an object property disclosure with auto-generated salt.
     * 
     * @param claimName the claim name
     * @param claimValue the claim value
     * @return new Disclosure for object property
     */
    public static Disclosure forObjectProperty(String claimName, Object claimValue) {
        if (claimName == null || claimName.trim().isEmpty()) {
            throw new InvalidDisclosureException("Claim name cannot be null or empty for object property");
        }
        
        String salt = SaltGenerator.generate();
        return new Disclosure(salt, claimName, claimValue);
    }
    
    /**
     * Get the salt value.
     * 
     * @return the salt
     */
    public String getSalt() {
        return salt;
    }
    
    /**
     * Get the claim name. Returns null for array element disclosures.
     * 
     * @return the claim name or null
     */
    public String getClaimName() {
        return claimName;
    }
    
    /**
     * Get the claim value.
     * 
     * @return the claim value
     */
    public Object getClaimValue() {
        return claimValue;
    }
    
    /**
     * Check if this disclosure is for an array element.
     * 
     * @return true if this is an array element disclosure
     */
    public boolean isArrayElement() {
        return claimName == null;
    }
    
    /**
     * Get the base64url-encoded disclosure string.
     * The disclosure is created by:
     * 1. Creating an array with [salt, claimName, claimValue] or [salt, claimValue]
     * 2. Converting to JSON
     * 3. Encoding as UTF-8 bytes
     * 4. Base64url encoding
     * 
     * @return the base64url-encoded disclosure string
     * @throws RuntimeException if JSON serialization fails
     */
    public String getDisclosure() {
        try {
            ArrayNode array = OBJECT_MAPPER.createArrayNode();
            array.add(salt);
            
            if (claimName != null) {
                // Object property: [salt, claimName, claimValue]
                array.add(claimName);
            }
            // Array element or object property: add claimValue
            array.addPOJO(claimValue);
            
            String json = OBJECT_MAPPER.writeValueAsString(array);
            byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);
            
            return Base64UrlUtils.encode(jsonBytes);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to create disclosure", e);
        }
    }
    
    /**
     * Compute the digest of this disclosure using the default hash algorithm (SHA-256).
     * 
     * @return the base64url-encoded digest
     */
    public String digest() {
        return digest(HashUtils.getDefaultHashAlgorithm());
    }
    
    /**
     * Compute the digest of this disclosure using the specified hash algorithm.
     * 
     * @param hashAlgorithm the hash algorithm to use
     * @return the base64url-encoded digest
     * @throws IllegalArgumentException if the hash algorithm is not supported
     */
    public String digest(String hashAlgorithm) {
        if (!HashUtils.isSupportedHashAlgorithm(hashAlgorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }
        
        String disclosure = getDisclosure();
        return HashUtils.computeDigest(disclosure, hashAlgorithm);
    }
    
    /**
     * Create a Map instance representing a selectively-disclosable array element.
     * Returns {"...": "digest_value"}
     * 
     * @return Map representing selectively-disclosable array element
     */
    public Map<String, Object> toArrayElement() {
        return toArrayElement(HashUtils.getDefaultHashAlgorithm());
    }
    
    /**
     * Create a Map instance representing a selectively-disclosable array element
     * with specified hash algorithm.
     * 
     * @param hashAlgorithm the hash algorithm to use for digest computation
     * @return Map representing selectively-disclosable array element
     */
    public Map<String, Object> toArrayElement(String hashAlgorithm) {
        Map<String, Object> element = new HashMap<>();
        element.put("...", digest(hashAlgorithm));
        return element;
    }
    
    /**
     * Parse a base64url-encoded disclosure string into a Disclosure object.
     * 
     * @param disclosureString the base64url-encoded disclosure string
     * @return the parsed Disclosure object
     * @throws SDJWTParseException if parsing fails
     */
    public static Disclosure parse(String disclosureString) {
        if (disclosureString == null || disclosureString.trim().isEmpty()) {
            throw new SDJWTParseException("Disclosure string cannot be null or empty");
        }
        
        try {
            byte[] decodedBytes = Base64UrlUtils.decode(disclosureString);
            String json = new String(decodedBytes, StandardCharsets.UTF_8);
            
            JsonNode arrayNode = OBJECT_MAPPER.readTree(json);
            
            if (!arrayNode.isArray()) {
                throw new SDJWTParseException("Disclosure must be a JSON array");
            }
            
            if (arrayNode.size() < 2 || arrayNode.size() > 3) {
                throw new SDJWTParseException("Disclosure array must have 2 or 3 elements");
            }
            
            String salt = arrayNode.get(0).asText();
            
            if (arrayNode.size() == 2) {
                // Array element disclosure: [salt, claimValue]
                Object claimValue = OBJECT_MAPPER.treeToValue(arrayNode.get(1), Object.class);
                return new Disclosure(salt, claimValue);
            } else {
                // Object property disclosure: [salt, claimName, claimValue]
                String claimName = arrayNode.get(1).asText();
                Object claimValue = OBJECT_MAPPER.treeToValue(arrayNode.get(2), Object.class);
                return new Disclosure(salt, claimName, claimValue);
            }
            
        } catch (Exception e) {
            throw new SDJWTParseException("Failed to parse disclosure: " + e.getMessage(), e);
        }
    }
    
    /**
     * Returns the base64url-encoded disclosure string.
     * This is equivalent to calling getDisclosure().
     * 
     * @return the base64url-encoded disclosure string
     */
    @Override
    public String toString() {
        return getDisclosure();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Disclosure that = (Disclosure) o;
        return Objects.equals(salt, that.salt) &&
               Objects.equals(claimName, that.claimName) &&
               Objects.equals(claimValue, that.claimValue);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(salt, claimName, claimValue);
    }
}