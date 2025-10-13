package org.omnione.did.oid4vc.core.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

/**
 * HashUtils provides utility methods for computing hash digests used in SD-JWT.
 * 
 * The SD-JWT specification uses hash digests to represent selectively-disclosable
 * claims in a privacy-preserving manner.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class HashUtils {
    
    /**
     * Default hash algorithm as specified in SD-JWT specification.
     */
    public static final String DEFAULT_HASH_ALGORITHM = "sha-256";
    
    /**
     * Set of supported hash algorithms according to IANA Named Information Hash Algorithm Registry.
     */
    private static final Set<String> SUPPORTED_ALGORITHMS = Set.of(
        "sha-1",        // SHA-1 (not recommended for new applications)
        "sha-256",      // SHA-256 (recommended)
        "sha-384",      // SHA-384
        "sha-512",      // SHA-512
        "sha3-256",     // SHA3-256
        "sha3-384",     // SHA3-384
        "sha3-512"      // SHA3-512
    );
    
    /**
     * Mapping from IANA algorithm names to Java algorithm names.
     */
    private static final java.util.Map<String, String> ALGORITHM_MAPPING = java.util.Map.of(
        "sha-1", "SHA-1",
        "sha-256", "SHA-256",
        "sha-384", "SHA-384",
        "sha-512", "SHA-512",
        "sha3-256", "SHA3-256",
        "sha3-384", "SHA3-384",
        "sha3-512", "SHA3-512"
    );
    
    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private HashUtils() {
        throw new UnsupportedOperationException("HashUtils is a utility class and cannot be instantiated");
    }
    
    /**
     * Get the default hash algorithm.
     * 
     * @return the default hash algorithm name
     */
    public static String getDefaultHashAlgorithm() {
        return DEFAULT_HASH_ALGORITHM;
    }
    
    /**
     * Check if a hash algorithm is supported.
     * 
     * @param algorithm the hash algorithm name (IANA format)
     * @return true if the algorithm is supported
     */
    public static boolean isSupportedHashAlgorithm(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        return SUPPORTED_ALGORITHMS.contains(algorithm.toLowerCase());
    }
    
    /**
     * Get the set of all supported hash algorithms.
     * 
     * @return unmodifiable set of supported algorithm names
     */
    public static Set<String> getSupportedAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }
    
    /**
     * Compute a hash digest of the input string using the specified algorithm.
     * The result is base64url-encoded.
     * 
     * @param input the input string to hash
     * @param algorithm the hash algorithm to use (IANA format)
     * @return the base64url-encoded hash digest
     * @throws IllegalArgumentException if the algorithm is not supported
     * @throws RuntimeException if hashing fails
     */
    public static String computeDigest(String input, String algorithm) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        if (!isSupportedHashAlgorithm(algorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
        
        try {
            String javaAlgorithm = ALGORITHM_MAPPING.get(algorithm.toLowerCase());
            MessageDigest digest = MessageDigest.getInstance(javaAlgorithm);
            
            byte[] inputBytes = input.getBytes(StandardCharsets.US_ASCII);
            byte[] hashBytes = digest.digest(inputBytes);
            
            return Base64UrlUtils.encode(hashBytes);
            
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + algorithm, e);
        }
    }
    
    /**
     * Compute a hash digest using the default algorithm (SHA-256).
     * 
     * @param input the input string to hash
     * @return the base64url-encoded hash digest
     * @throws RuntimeException if hashing fails
     */
    public static String computeDigest(String input) {
        return computeDigest(input, DEFAULT_HASH_ALGORITHM);
    }
    
    /**
     * Compute hash digests for multiple inputs using the same algorithm.
     * 
     * @param inputs the input strings to hash
     * @param algorithm the hash algorithm to use
     * @return array of base64url-encoded hash digests
     * @throws IllegalArgumentException if algorithm is not supported or inputs is null
     */
    public static String[] computeDigests(String[] inputs, String algorithm) {
        if (inputs == null) {
            throw new IllegalArgumentException("Inputs cannot be null");
        }
        
        String[] digests = new String[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            digests[i] = computeDigest(inputs[i], algorithm);
        }
        return digests;
    }
    
    /**
     * Compute hash digests for multiple inputs using the default algorithm.
     * 
     * @param inputs the input strings to hash
     * @return array of base64url-encoded hash digests
     */
    public static String[] computeDigests(String[] inputs) {
        return computeDigests(inputs, DEFAULT_HASH_ALGORITHM);
    }
    
    /**
     * Verify that a hash digest matches the input using the specified algorithm.
     * 
     * @param input the original input string
     * @param expectedDigest the expected hash digest (base64url-encoded)
     * @param algorithm the hash algorithm used
     * @return true if the digest matches
     * @throws IllegalArgumentException if parameters are invalid
     */
    public static boolean verifyDigest(String input, String expectedDigest, String algorithm) {
        if (expectedDigest == null) {
            throw new IllegalArgumentException("Expected digest cannot be null");
        }
        
        String computedDigest = computeDigest(input, algorithm);
        return computedDigest.equals(expectedDigest);
    }
    
    /**
     * Verify a hash digest using the default algorithm.
     * 
     * @param input the original input string
     * @param expectedDigest the expected hash digest
     * @return true if the digest matches
     */
    public static boolean verifyDigest(String input, String expectedDigest) {
        return verifyDigest(input, expectedDigest, DEFAULT_HASH_ALGORITHM);
    }
    
    /**
     * Get the output length in bytes for a given hash algorithm.
     * 
     * @param algorithm the hash algorithm name
     * @return the hash output length in bytes
     * @throws IllegalArgumentException if algorithm is not supported
     */
    public static int getHashLength(String algorithm) {
        if (!isSupportedHashAlgorithm(algorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
        
        return switch (algorithm.toLowerCase()) {
            case "sha-1" -> 20;      // 160 bits
            case "sha-256" -> 32;    // 256 bits
            case "sha-384" -> 48;    // 384 bits
            case "sha-512" -> 64;    // 512 bits
            case "sha3-256" -> 32;   // 256 bits
            case "sha3-384" -> 48;   // 384 bits
            case "sha3-512" -> 64;   // 512 bits
            default -> throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        };
    }
    
    /**
     * Get the security strength in bits for a given hash algorithm.
     * 
     * @param algorithm the hash algorithm name
     * @return the security strength in bits
     * @throws IllegalArgumentException if algorithm is not supported
     */
    public static int getSecurityStrength(String algorithm) {
        if (!isSupportedHashAlgorithm(algorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
        
        return switch (algorithm.toLowerCase()) {
            case "sha-1" -> 80;      // Reduced due to known attacks
            case "sha-256" -> 128;   // 128-bit security
            case "sha-384" -> 192;   // 192-bit security
            case "sha-512" -> 256;   // 256-bit security
            case "sha3-256" -> 128;  // 128-bit security
            case "sha3-384" -> 192;  // 192-bit security
            case "sha3-512" -> 256;  // 256-bit security
            default -> throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        };
    }
    
    /**
     * Get the recommended hash algorithm for a given security level.
     * 
     * @param securityLevel the desired security level in bits
     * @return the recommended hash algorithm
     * @throws IllegalArgumentException if security level is not supported
     */
    public static String getRecommendedAlgorithm(int securityLevel) {
        return switch (securityLevel) {
            case 80 -> "sha-1";      // Not recommended for new applications
            case 128 -> "sha-256";   // Recommended
            case 192 -> "sha-384";   // High security
            case 256 -> "sha-512";   // Very high security
            default -> throw new IllegalArgumentException(
                "Unsupported security level: " + securityLevel + 
                ". Supported levels: 80, 128, 192, 256");
        };
    }
    
    /**
     * Check if an algorithm is considered secure for new applications.
     * 
     * @param algorithm the hash algorithm name
     * @return true if the algorithm is considered secure
     */
    public static boolean isSecureAlgorithm(String algorithm) {
        if (!isSupportedHashAlgorithm(algorithm)) {
            return false;
        }
        
        // SHA-1 is not considered secure for new applications
        return !algorithm.toLowerCase().equals("sha-1");
    }
    
    /**
     * Validate that a hash algorithm is supported and secure.
     * 
     * @param algorithm the hash algorithm to validate
     * @throws IllegalArgumentException if algorithm is not supported or not secure
     */
    public static void validateSecureAlgorithm(String algorithm) {
        if (!isSupportedHashAlgorithm(algorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
        if (!isSecureAlgorithm(algorithm)) {
            throw new IllegalArgumentException("Hash algorithm is not considered secure: " + algorithm);
        }
    }
    
    /**
     * Create a hash digest validator for a specific algorithm.
     * 
     * @param algorithm the hash algorithm to use
     * @return a function that computes digests for the specified algorithm
     */
    public static java.util.function.Function<String, String> createDigestFunction(String algorithm) {
        validateSecureAlgorithm(algorithm);
        return input -> computeDigest(input, algorithm);
    }
}