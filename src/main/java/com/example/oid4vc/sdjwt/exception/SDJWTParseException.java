package com.example.oid4vc.sdjwt.exception;

/**
 * Exception thrown when parsing of SD-JWT components fails.
 * 
 * This exception is thrown when there are issues parsing SD-JWT strings,
 * disclosure strings, or other SD-JWT related data structures.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWTParseException extends SDJWTException {
    
    /**
     * Constructs a new SD-JWT parse exception with the specified detail message.
     * 
     * @param message the detail message explaining the parsing error
     */
    public SDJWTParseException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new SD-JWT parse exception with the specified detail message and cause.
     * 
     * @param message the detail message explaining the parsing error
     * @param cause the underlying cause of the parsing failure
     */
    public SDJWTParseException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructs a new SD-JWT parse exception with the specified cause.
     * 
     * @param cause the underlying cause of the parsing failure
     */
    public SDJWTParseException(Throwable cause) {
        super("SD-JWT parsing failed", cause);
    }
}