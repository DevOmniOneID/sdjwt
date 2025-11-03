package org.omnione.did.sdjwt.util;

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
    

}