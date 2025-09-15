package com.example.oid4vc.sdjwt.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Base64UrlUtils provides utility methods for Base64URL encoding and decoding
 * as specified in RFC 4648 Section 5.
 * 
 * Base64URL encoding is used throughout SD-JWT for encoding disclosures,
 * hash digests, and other binary data in a URL-safe manner.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class Base64UrlUtils {
    
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    
    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private Base64UrlUtils() {
        throw new UnsupportedOperationException("Base64UrlUtils is a utility class and cannot be instantiated");
    }
    
    /**
     * Encode a byte array to Base64URL string without padding.
     * 
     * @param data the byte array to encode
     * @return the Base64URL encoded string
     * @throws IllegalArgumentException if data is null
     */
    public static String encode(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        return ENCODER.encodeToString(data);
    }
    
    /**
     * Encode a string to Base64URL using UTF-8 encoding.
     * 
     * @param data the string to encode
     * @return the Base64URL encoded string
     * @throws IllegalArgumentException if data is null
     */
    public static String encode(String data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        return encode(data.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Decode a Base64URL string to byte array.
     * 
     * @param encoded the Base64URL encoded string
     * @return the decoded byte array
     * @throws IllegalArgumentException if encoded string is null or invalid
     */
    public static byte[] decode(String encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Encoded string cannot be null");
        }
        
        try {
            return DECODER.decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64URL encoding: " + e.getMessage(), e);
        }
    }
    
    /**
     * Decode a Base64URL string to UTF-8 string.
     * 
     * @param encoded the Base64URL encoded string
     * @return the decoded UTF-8 string
     * @throws IllegalArgumentException if encoded string is null or invalid
     */
    public static String decodeToString(String encoded) {
        byte[] decoded = decode(encoded);
        return new String(decoded, StandardCharsets.UTF_8);
    }
    
    /**
     * Check if a string is valid Base64URL encoding.
     * 
     * @param encoded the string to validate
     * @return true if the string is valid Base64URL
     */
    public static boolean isValid(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return false;
        }
        
        try {
            decode(encoded);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Validate that a string is proper Base64URL encoding.
     * 
     * @param encoded the string to validate
     * @throws IllegalArgumentException if the string is not valid Base64URL
     */
    public static void validate(String encoded) {
        if (!isValid(encoded)) {
            throw new IllegalArgumentException("Invalid Base64URL encoding: " + encoded);
        }
    }
    
    /**
     * Encode multiple byte arrays to Base64URL strings.
     * 
     * @param dataArrays the byte arrays to encode
     * @return array of Base64URL encoded strings
     * @throws IllegalArgumentException if dataArrays is null
     */
    public static String[] encodeMultiple(byte[]... dataArrays) {
        if (dataArrays == null) {
            throw new IllegalArgumentException("Data arrays cannot be null");
        }
        
        String[] encoded = new String[dataArrays.length];
        for (int i = 0; i < dataArrays.length; i++) {
            encoded[i] = encode(dataArrays[i]);
        }
        return encoded;
    }
    
    /**
     * Encode multiple strings to Base64URL strings.
     * 
     * @param dataStrings the strings to encode
     * @return array of Base64URL encoded strings
     * @throws IllegalArgumentException if dataStrings is null
     */
    public static String[] encodeMultiple(String... dataStrings) {
        if (dataStrings == null) {
            throw new IllegalArgumentException("Data strings cannot be null");
        }
        
        String[] encoded = new String[dataStrings.length];
        for (int i = 0; i < dataStrings.length; i++) {
            encoded[i] = encode(dataStrings[i]);
        }
        return encoded;
    }
    
    /**
     * Decode multiple Base64URL strings to byte arrays.
     * 
     * @param encodedStrings the Base64URL encoded strings
     * @return array of decoded byte arrays
     * @throws IllegalArgumentException if encodedStrings is null or any string is invalid
     */
    public static byte[][] decodeMultiple(String... encodedStrings) {
        if (encodedStrings == null) {
            throw new IllegalArgumentException("Encoded strings cannot be null");
        }
        
        byte[][] decoded = new byte[encodedStrings.length][];
        for (int i = 0; i < encodedStrings.length; i++) {
            decoded[i] = decode(encodedStrings[i]);
        }
        return decoded;
    }
    
    /**
     * Decode multiple Base64URL strings to UTF-8 strings.
     * 
     * @param encodedStrings the Base64URL encoded strings
     * @return array of decoded UTF-8 strings
     * @throws IllegalArgumentException if encodedStrings is null or any string is invalid
     */
    public static String[] decodeMultipleToStrings(String... encodedStrings) {
        if (encodedStrings == null) {
            throw new IllegalArgumentException("Encoded strings cannot be null");
        }
        
        String[] decoded = new String[encodedStrings.length];
        for (int i = 0; i < encodedStrings.length; i++) {
            decoded[i] = decodeToString(encodedStrings[i]);
        }
        return decoded;
    }
    
    /**
     * Get the estimated decoded length for a Base64URL encoded string.
     * This is an approximation since Base64URL doesn't use padding.
     * 
     * @param encodedLength the length of the encoded string
     * @return the estimated decoded length in bytes
     */
    public static int estimateDecodedLength(int encodedLength) {
        // Base64 encodes 3 bytes into 4 characters
        // For Base64URL without padding, we need to estimate
        return (encodedLength * 3) / 4;
    }
    
    /**
     * Get the encoded length for a given input length.
     * 
     * @param inputLength the length of the input in bytes
     * @return the length of the Base64URL encoded string
     */
    public static int getEncodedLength(int inputLength) {
        // Base64 encodes 3 bytes into 4 characters
        // Without padding, the length formula is ceiling(inputLength * 4 / 3)
        return (inputLength * 4 + 2) / 3;
    }
    
    /**
     * Safely encode data that might contain sensitive information.
     * This method clears the input array after encoding for security.
     * 
     * @param sensitiveData the sensitive byte array to encode (will be cleared)
     * @return the Base64URL encoded string
     * @throws IllegalArgumentException if sensitiveData is null
     */
    public static String encodeAndClear(byte[] sensitiveData) {
        if (sensitiveData == null) {
            throw new IllegalArgumentException("Sensitive data cannot be null");
        }
        
        try {
            return encode(sensitiveData);
        } finally {
            // Clear the sensitive data
            java.util.Arrays.fill(sensitiveData, (byte) 0);
        }
    }
    
    /**
     * Compare two Base64URL encoded strings for equality without decoding.
     * This is more efficient than decoding both strings for comparison.
     * 
     * @param encoded1 the first Base64URL encoded string
     * @param encoded2 the second Base64URL encoded string
     * @return true if the encoded strings represent the same data
     */
    public static boolean equals(String encoded1, String encoded2) {
        if (encoded1 == null && encoded2 == null) {
            return true;
        }
        if (encoded1 == null || encoded2 == null) {
            return false;
        }
        
        // Base64URL comparison can be done directly on the encoded strings
        return encoded1.equals(encoded2);
    }
    
    /**
     * Create a Base64URL encoder function.
     * 
     * @return a function that encodes byte arrays to Base64URL strings
     */
    public static java.util.function.Function<byte[], String> createEncoder() {
        return Base64UrlUtils::encode;
    }
    
    /**
     * Create a Base64URL decoder function.
     * 
     * @return a function that decodes Base64URL strings to byte arrays
     */
    public static java.util.function.Function<String, byte[]> createDecoder() {
        return Base64UrlUtils::decode;
    }
}