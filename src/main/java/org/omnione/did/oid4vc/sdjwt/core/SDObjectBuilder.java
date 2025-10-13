package org.omnione.did.oid4vc.sdjwt.core;

import org.omnione.did.oid4vc.core.util.HashUtils;
import org.omnione.did.oid4vc.core.util.SaltGenerator;

import java.util.*;

/**
 * SDObjectBuilder is a utility class to create a Map instance that represents
 * a JSON object which may contain the "_sd" array for selective disclosure.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDObjectBuilder {
    
    private final String hashAlgorithm;
    private final Map<String, Object> claims;
    private final List<String> sdArray;
    
    /**
     * Create an SDObjectBuilder instance with the default hash algorithm (SHA-256).
     */
    public SDObjectBuilder() {
        this(HashUtils.getDefaultHashAlgorithm());
    }
    
    /**
     * Create an SDObjectBuilder instance with the specified hash algorithm.
     * 
     * @param hashAlgorithm the hash algorithm to use for digest computation
     * @throws IllegalArgumentException if the hash algorithm is not supported
     */
    public SDObjectBuilder(String hashAlgorithm) {
        if (!HashUtils.isSupportedHashAlgorithm(hashAlgorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
        }
        
        this.hashAlgorithm = hashAlgorithm;
        this.claims = new LinkedHashMap<>();
        this.sdArray = new ArrayList<>();
    }
    
    /**
     * Add a normal (non-selectively-disclosable) claim.
     * 
     * @param claimName the claim name
     * @param claimValue the claim value
     * @return this SDObjectBuilder instance for method chaining
     * @throws IllegalArgumentException if claimName is null or reserved
     */
    public SDObjectBuilder putClaim(String claimName, Object claimValue) {
        validateClaimName(claimName);
        claims.put(claimName, claimValue);
        return this;
    }
    
    /**
     * Add multiple normal claims from a Map.
     * 
     * @param claims the claims to add
     * @return this SDObjectBuilder instance for method chaining
     * @throws IllegalArgumentException if any claim name is invalid
     */
    public SDObjectBuilder putClaims(Map<String, Object> claims) {
        if (claims != null) {
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                putClaim(entry.getKey(), entry.getValue());
            }
        }
        return this;
    }
    
    /**
     * Add a selectively-disclosable claim using an existing Disclosure.
     * 
     * @param disclosure the Disclosure object
     * @return this SDObjectBuilder instance for method chaining
     * @throws IllegalArgumentException if disclosure is null or for array element
     */
    public SDObjectBuilder putSDClaim(Disclosure disclosure) {
        if (disclosure == null) {
            throw new IllegalArgumentException("Disclosure cannot be null");
        }
        if (disclosure.isArrayElement()) {
            throw new IllegalArgumentException("Array element disclosures cannot be used for object properties");
        }
        
        String digest = disclosure.digest(hashAlgorithm);
        sdArray.add(digest);
        return this;
    }
    
    /**
     * Add a selectively-disclosable claim by creating a new Disclosure.
     * 
     * @param claimName the claim name
     * @param claimValue the claim value
     * @return this SDObjectBuilder instance for method chaining
     * @throws IllegalArgumentException if claimName is invalid
     */
    public SDObjectBuilder putSDClaim(String claimName, Object claimValue) {
        validateClaimName(claimName);
        Disclosure disclosure = new Disclosure(claimName, claimValue);
        return putSDClaim(disclosure);
    }
    
    /**
     * Add a selectively-disclosable claim with explicit salt.
     * 
     * @param salt the salt value
     * @param claimName the claim name
     * @param claimValue the claim value
     * @return this SDObjectBuilder instance for method chaining
     * @throws IllegalArgumentException if parameters are invalid
     */
    public SDObjectBuilder putSDClaim(String salt, String claimName, Object claimValue) {
        validateClaimName(claimName);
        if (salt == null || salt.trim().isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }
        
        Disclosure disclosure = new Disclosure(salt, claimName, claimValue);
        return putSDClaim(disclosure);
    }
    
    /**
     * Add a decoy digest to make it more difficult for attackers to determine
     * the original number of claims.
     * 
     * @return this SDObjectBuilder instance for method chaining
     */
    public SDObjectBuilder putDecoyDigest() {
        // Generate a random disclosure for decoy purposes
        String decoySalt = SaltGenerator.generate();
        String decoyClaimName = "_decoy_" + System.nanoTime();
        String decoyClaimValue = "decoy_value_" + UUID.randomUUID().toString();
        
        Disclosure decoyDisclosure = new Disclosure(decoySalt, decoyClaimName, decoyClaimValue);
        String decoyDigest = decoyDisclosure.digest(hashAlgorithm);
        
        sdArray.add(decoyDigest);
        return this;
    }
    
    /**
     * Add the specified number of decoy digests.
     * 
     * @param count the number of decoy digests to add
     * @return this SDObjectBuilder instance for method chaining
     * @throws IllegalArgumentException if count is negative
     */
    public SDObjectBuilder putDecoyDigests(int count) {
        if (count < 0) {
            throw new IllegalArgumentException("Count cannot be negative");
        }
        
        for (int i = 0; i < count; i++) {
            putDecoyDigest();
        }
        return this;
    }
    
    /**
     * Build the Map instance representing the JSON object.
     * 
     * @return the Map instance
     */
    public Map<String, Object> build() {
        return build(false);
    }
    
    /**
     * Build the Map instance representing the JSON object.
     * 
     * @param includeHashAlg whether to include the "_sd_alg" claim
     * @return the Map instance
     */
    public Map<String, Object> build(boolean includeHashAlg) {
        Map<String, Object> result = new LinkedHashMap<>(claims);
        
        // Add _sd array if there are any SD claims
        if (!sdArray.isEmpty()) {
            // Shuffle the SD array to make it harder to correlate with original claims
            List<String> shuffledSdArray = new ArrayList<>(sdArray);
            Collections.shuffle(shuffledSdArray);
            result.put("_sd", shuffledSdArray);
        }
        
        // Add hash algorithm if requested
        if (includeHashAlg) {
            result.put("_sd_alg", hashAlgorithm);
        }
        
        return result;
    }
    
    /**
     * Get the current hash algorithm being used.
     * 
     * @return the hash algorithm
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }
    
    /**
     * Get the number of SD claims (including decoy digests) that have been added.
     * 
     * @return the number of SD claims
     */
    public int getSDClaimCount() {
        return sdArray.size();
    }
    
    /**
     * Get the number of normal claims that have been added.
     * 
     * @return the number of normal claims
     */
    public int getClaimCount() {
        return claims.size();
    }
    
    /**
     * Check if any SD claims have been added.
     * 
     * @return true if there are SD claims
     */
    public boolean hasSDClaims() {
        return !sdArray.isEmpty();
    }
    
    /**
     * Clear all claims and SD claims.
     * 
     * @return this SDObjectBuilder instance for method chaining
     */
    public SDObjectBuilder clear() {
        claims.clear();
        sdArray.clear();
        return this;
    }
    
    /**
     * Create a copy of this SDObjectBuilder.
     * 
     * @return a new SDObjectBuilder with the same hash algorithm and claims
     */
    public SDObjectBuilder copy() {
        SDObjectBuilder copy = new SDObjectBuilder(hashAlgorithm);
        copy.claims.putAll(this.claims);
        copy.sdArray.addAll(this.sdArray);
        return copy;
    }
    
    /**
     * Validate that a claim name is not null, empty, or reserved.
     * 
     * @param claimName the claim name to validate
     * @throws IllegalArgumentException if the claim name is invalid
     */
    private void validateClaimName(String claimName) {
        if (claimName == null || claimName.trim().isEmpty()) {
            throw new IllegalArgumentException("Claim name cannot be null or empty");
        }
        
        // Check for reserved claim names
        if ("_sd".equals(claimName) || "_sd_alg".equals(claimName)) {
            throw new IllegalArgumentException("Claim name '" + claimName + "' is reserved for SD-JWT");
        }
    }
    
    @Override
    public String toString() {
        return String.format("SDObjectBuilder{hashAlgorithm='%s', claims=%d, sdClaims=%d}", 
                hashAlgorithm, claims.size(), sdArray.size());
    }
}