package org.omnione.did.oid4vc.sdjwt.exception;

import org.omnione.did.oid4vc.core.exception.OID4VCException;

/**
 * Exception class for SD-JWT specific exceptions.
 *
 * This exception is thrown when errors occur during SD-JWT specific operations,
 * including selective disclosure processing, disclosure validation, SD-JWT parsing,
 * and SD-JWT building operations.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWTException extends OID4VCException {

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