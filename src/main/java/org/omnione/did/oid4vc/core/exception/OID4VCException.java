package org.omnione.did.oid4vc.core.exception;

/**
 * Base exception class for all OID4VC related exceptions.
 *
 * This is the parent class for all exceptions that can occur during
 * OpenID for Verifiable Credentials processing, including JWT operations,
 * VP token processing, credential format handling, and cryptographic operations.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class OID4VCException extends RuntimeException {

  /**
   * Constructs a new OID4VC exception with the specified detail message.
   *
   * @param message the detail message
   */
  public OID4VCException(String message) {
    super(message);
  }

  /**
   * Constructs a new OID4VC exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   */
  public OID4VCException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new OID4VC exception with the specified cause.
   *
   * @param cause the cause of this exception
   */
  public OID4VCException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructs a new OID4VC exception with the specified detail message,
   * cause, suppression enabled or disabled, and writable stack trace
   * enabled or disabled.
   *
   * @param message the detail message
   * @param cause the cause of this exception
   * @param enableSuppression whether or not suppression is enabled or disabled
   * @param writableStackTrace whether or not the stack trace should be writable
   */
  protected OID4VCException(String message, Throwable cause,
      boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}