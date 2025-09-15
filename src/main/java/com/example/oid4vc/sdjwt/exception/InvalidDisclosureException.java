package com.example.oid4vc.sdjwt.exception;

/**
 * Exception thrown when a disclosure is invalid or malformed.
 * 
 * This exception is thrown when creating or validating disclosures
 * with invalid parameters such as null/empty salts, invalid claim names,
 * or malformed disclosure structures.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class InvalidDisclosureException extends SDJWTException {
    
    /**
     * Constructs a new invalid disclosure exception with the specified detail message.
     * 
     * @param message the detail message explaining why the disclosure is invalid
     */
    public InvalidDisclosureException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new invalid disclosure exception with the specified detail message and cause.
     * 
     * @param message the detail message explaining why the disclosure is invalid
     * @param cause the underlying cause of the validation failure
     */
    public InvalidDisclosureException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructs a new invalid disclosure exception with the specified cause.
     * 
     * @param cause the underlying cause of the validation failure
     */
    public InvalidDisclosureException(Throwable cause) {
        super("Invalid disclosure", cause);
    }
}