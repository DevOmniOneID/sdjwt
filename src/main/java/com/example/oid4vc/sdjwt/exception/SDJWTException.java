package com.example.oid4vc.sdjwt.exception;

/**
 * Base exception class for all SD-JWT related exceptions.
 * 
 * This is the parent class for all exceptions that can occur during
 * SD-JWT processing, including parsing, validation, and encoding/decoding operations.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWTException extends RuntimeException {
    
    /**
     * Constructs a new SD-JWT exception with the specified detail message.
     * 
     * @param message the detail message
     */
    public SDJWTException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new SD-JWT exception with the specified detail message and cause.
     * 
     * @param message the detail message
     * @param cause the cause of this exception
     */
    public SDJWTException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructs a new SD-JWT exception with the specified cause.
     * 
     * @param cause the cause of this exception
     */
    public SDJWTException(Throwable cause) {
        super(cause);
    }
    
    /**
     * Constructs a new SD-JWT exception with the specified detail message,
     * cause, suppression enabled or disabled, and writable stack trace
     * enabled or disabled.
     * 
     * @param message the detail message
     * @param cause the cause of this exception
     * @param enableSuppression whether or not suppression is enabled or disabled
     * @param writableStackTrace whether or not the stack trace should be writable
     */
    protected SDJWTException(String message, Throwable cause, 
                           boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}