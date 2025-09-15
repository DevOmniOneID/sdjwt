package com.example.oid4vc.sdjwt.codec;

import com.example.oid4vc.sdjwt.core.Disclosure;
import com.example.oid4vc.sdjwt.core.SDObjectBuilder;
import com.example.oid4vc.sdjwt.util.HashUtils;

import java.util.*;

/**
 * SDObjectEncoder is a utility to make elements in a map or a list
 * selectively-disclosable recursively.
 * 
 * This class automatically adds decoy digests unless the decoy magnification
 * ratio is set to 0.0.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDObjectEncoder {
    
    private final String hashAlgorithm;
    private final double decoyMagnificationMin;
    private final double decoyMagnificationMax;
    private final Random random;
    private final List<Disclosure> generatedDisclosures;
    
    /**
     * Create an SDObjectEncoder with default parameters.
     * - Hash algorithm: SHA-256
     * - Decoy magnification: 0.0 to 2.0 (0 to 200% additional decoy digests)
     */
    public SDObjectEncoder() {
        this(HashUtils.getDefaultHashAlgorithm(), 0.0, 2.0);
    }
    
    /**
     * Create an SDObjectEncoder with specified hash algorithm and default decoy settings.
     * 
     * @param hashAlgorithm the hash algorithm to use
     */
    public SDObjectEncoder(String hashAlgorithm) {
        this(hashAlgorithm, 0.0, 2.0);
    }
    
    /**
     * Create an SDObjectEncoder with specified parameters.
     * 
     * @param hashAlgorithm the hash algorithm to use
     * @param decoyMagnificationMin minimum decoy magnification ratio (0.0 = no decoys)
     * @param decoyMagnificationMax maximum decoy magnification ratio
     * @throws IllegalArgumentException if parameters are invalid
     */
    public SDObjectEncoder(String hashAlgorithm, double decoyMagnificationMin, double decoyMagnificationMax) {
        if (!HashUtils.isSupportedHashAlgorithm(hashAlgorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }
        if (decoyMagnificationMin < 0.0) {
            throw new IllegalArgumentException("Decoy magnification min cannot be negative");
        }
        if (decoyMagnificationMax < decoyMagnificationMin) {
            throw new IllegalArgumentException("Decoy magnification max cannot be less than min");
        }
        
        this.hashAlgorithm = hashAlgorithm;
        this.decoyMagnificationMin = decoyMagnificationMin;
        this.decoyMagnificationMax = decoyMagnificationMax;
        this.random = new Random();
        this.generatedDisclosures = new ArrayList<>();
    }
    
    /**
     * Set the decoy magnification ratios.
     * 
     * @param min minimum decoy magnification ratio
     * @param max maximum decoy magnification ratio
     * @return this encoder for method chaining
     */
    public SDObjectEncoder setDecoyMagnification(double min, double max) {
        if (min < 0.0) {
            throw new IllegalArgumentException("Decoy magnification min cannot be negative");
        }
        if (max < min) {
            throw new IllegalArgumentException("Decoy magnification max cannot be less than min");
        }
        
        return new SDObjectEncoder(hashAlgorithm, min, max);
    }
    
    /**
     * Encode a Map by making its elements selectively-disclosable recursively.
     * 
     * @param originalMap the original map to encode
     * @return the encoded map with "_sd" arrays
     * @throws IllegalArgumentException if originalMap is null
     */
    public Map<String, Object> encode(Map<String, Object> originalMap) {
        if (originalMap == null) {
            throw new IllegalArgumentException("Original map cannot be null");
        }
        
        // Clear previous disclosures
        generatedDisclosures.clear();
        
        return encodeMapRecursive(originalMap, true);
    }
    
    /**
     * Encode a List by making its elements selectively-disclosable recursively.
     * 
     * @param originalList the original list to encode
     * @return the encoded list with selective disclosure elements
     * @throws IllegalArgumentException if originalList is null
     */
    public List<Object> encode(List<Object> originalList) {
        if (originalList == null) {
            throw new IllegalArgumentException("Original list cannot be null");
        }
        
        // Clear previous disclosures
        generatedDisclosures.clear();
        
        return encodeListRecursive(originalList);
    }
    
    /**
     * Get the disclosures generated during the last encoding operation.
     * 
     * @return list of generated disclosures
     */
    public List<Disclosure> getDisclosures() {
        return new ArrayList<>(generatedDisclosures);
    }
    
    /**
     * Recursively encode a map.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> encodeMapRecursive(Map<String, Object> map, boolean makeSD) {
        if (map == null || map.isEmpty()) {
            return new LinkedHashMap<>(map != null ? map : Collections.emptyMap());
        }
        
        SDObjectBuilder builder = new SDObjectBuilder(hashAlgorithm);
        
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            // Skip reserved SD-JWT claim names
            if ("_sd".equals(key) || "_sd_alg".equals(key)) {
                builder.putClaim(key, value);
                continue;
            }
            
            // Recursively process nested structures
            Object processedValue = processValue(value);
            
            if (makeSD && shouldMakeSelective(key, processedValue)) {
                // Make this claim selectively disclosable
                Disclosure disclosure = new Disclosure(key, processedValue);
                generatedDisclosures.add(disclosure);
                builder.putSDClaim(disclosure);
            } else {
                // Keep as regular claim
                builder.putClaim(key, processedValue);
            }
        }
        
        // Add decoy digests if enabled
        if (makeSD && decoyMagnificationMax > 0.0) {
            int sdClaimCount = builder.getSDClaimCount();
            if (sdClaimCount > 0) {
                int decoyCount = calculateDecoyCount(sdClaimCount);
                builder.putDecoyDigests(decoyCount);
            }
        }
        
        return builder.build(true); // Include _sd_alg
    }
    
    /**
     * Recursively encode a list.
     */
    @SuppressWarnings("unchecked")
    private List<Object> encodeListRecursive(List<Object> list) {
        if (list == null || list.isEmpty()) {
            return new ArrayList<>(list != null ? list : Collections.emptyList());
        }
        
        List<Object> result = new ArrayList<>();
        
        for (Object item : list) {
            // Recursively process nested structures
            Object processedItem = processValue(item);
            
            if (shouldMakeSelective(null, processedItem)) {
                // Make this array element selectively disclosable
                Disclosure disclosure = new Disclosure(processedItem);
                generatedDisclosures.add(disclosure);
                result.add(disclosure.toArrayElement(hashAlgorithm));
            } else {
                result.add(processedItem);
            }
        }
        
        return result;
    }
    
    /**
     * Process a value recursively, handling nested maps and lists.
     */
    @SuppressWarnings("unchecked")
    private Object processValue(Object value) {
        if (value instanceof Map) {
            return encodeMapRecursive((Map<String, Object>) value, false);
        } else if (value instanceof List) {
            return encodeListRecursive((List<Object>) value);
        } else {
            return value;
        }
    }
    
    /**
     * Determine if a claim/value should be made selectively disclosable.
     * This is a simple implementation that makes most claims selective.
     * Override this method to implement custom logic.
     */
    protected boolean shouldMakeSelective(String claimName, Object claimValue) {
        // Don't make null values selective
        if (claimValue == null) {
            return false;
        }
        
        // Don't make system/structural claims selective by default
        if (claimName != null) {
            Set<String> systemClaims = Set.of(
                "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
                "typ", "alg", "kid", "vct", "cnf"
            );
            if (systemClaims.contains(claimName)) {
                return false;
            }
        }
        
        // Make most other claims selective by default
        return true;
    }
    
    /**
     * Calculate the number of decoy digests to add based on the number of real SD claims.
     */
    private int calculateDecoyCount(int realSdClaimCount) {
        if (decoyMagnificationMax <= 0.0) {
            return 0;
        }
        
        double magnification = decoyMagnificationMin;
        if (decoyMagnificationMax > decoyMagnificationMin) {
            magnification += random.nextDouble() * (decoyMagnificationMax - decoyMagnificationMin);
        }
        
        return (int) Math.round(realSdClaimCount * magnification);
    }
    
    /**
     * Get the hash algorithm being used.
     * 
     * @return the hash algorithm
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }
    
    /**
     * Get the minimum decoy magnification ratio.
     * 
     * @return the minimum decoy magnification ratio
     */
    public double getDecoyMagnificationMin() {
        return decoyMagnificationMin;
    }
    
    /**
     * Get the maximum decoy magnification ratio.
     * 
     * @return the maximum decoy magnification ratio
     */
    public double getDecoyMagnificationMax() {
        return decoyMagnificationMax;
    }
    
    @Override
    public String toString() {
        return String.format("SDObjectEncoder{hashAlgorithm='%s', decoyRange=[%.1f,%.1f], disclosures=%d}", 
                hashAlgorithm, decoyMagnificationMin, decoyMagnificationMax, generatedDisclosures.size());
    }
}