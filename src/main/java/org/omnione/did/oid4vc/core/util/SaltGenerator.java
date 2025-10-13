package org.omnione.did.oid4vc.core.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * SaltGenerator provides utility methods for generating cryptographically secure
 * salt values for SD-JWT disclosures.
 *
 * The SD-JWT specification recommends that a salt have 128-bit or higher entropy
 * and be base64url-encoded.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SaltGenerator {

  /**
   * Default salt length in bytes (128-bit = 16 bytes).
   */
  public static final int DEFAULT_SALT_LENGTH = 16;

  /**
   * Minimum recommended salt length in bytes.
   */
  public static final int MIN_SALT_LENGTH = 8;

  /**
   * Maximum practical salt length in bytes.
   */
  public static final int MAX_SALT_LENGTH = 64;

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

  /**
   * Private constructor to prevent instantiation of utility class.
   */
  private SaltGenerator() {
    throw new UnsupportedOperationException("SaltGenerator is a utility class and cannot be instantiated");
  }

  /**
   * Generate a cryptographically secure salt with default length (128-bit).
   *
   * @return base64url-encoded salt string
   */
  public static String generate() {
    return generate(DEFAULT_SALT_LENGTH);
  }

  /**
   * Generate a cryptographically secure salt with specified length.
   *
   * @param lengthInBytes the length of the salt in bytes
   * @return base64url-encoded salt string
   * @throws IllegalArgumentException if length is not within valid range
   */
  public static String generate(int lengthInBytes) {
    if (lengthInBytes < MIN_SALT_LENGTH) {
      throw new IllegalArgumentException(
          String.format("Salt length must be at least %d bytes, but was %d",
              MIN_SALT_LENGTH, lengthInBytes));
    }
    if (lengthInBytes > MAX_SALT_LENGTH) {
      throw new IllegalArgumentException(
          String.format("Salt length must be at most %d bytes, but was %d",
              MAX_SALT_LENGTH, lengthInBytes));
    }

    byte[] saltBytes = new byte[lengthInBytes];
    SECURE_RANDOM.nextBytes(saltBytes);
    return BASE64_URL_ENCODER.encodeToString(saltBytes);
  }

  /**
   * Generate multiple salts with default length.
   *
   * @param count the number of salts to generate
   * @return array of base64url-encoded salt strings
   * @throws IllegalArgumentException if count is negative
   */
  public static String[] generateMultiple(int count) {
    return generateMultiple(count, DEFAULT_SALT_LENGTH);
  }

  /**
   * Generate multiple salts with specified length.
   *
   * @param count the number of salts to generate
   * @param lengthInBytes the length of each salt in bytes
   * @return array of base64url-encoded salt strings
   * @throws IllegalArgumentException if parameters are invalid
   */
  public static String[] generateMultiple(int count, int lengthInBytes) {
    if (count < 0) {
      throw new IllegalArgumentException("Count cannot be negative");
    }

    String[] salts = new String[count];
    for (int i = 0; i < count; i++) {
      salts[i] = generate(lengthInBytes);
    }
    return salts;
  }

  /**
   * Validate that a string is a valid salt format.
   * A valid salt should be base64url-encoded and have sufficient entropy.
   *
   * @param salt the salt string to validate
   * @return true if the salt is valid
   */
  public static boolean isValid(String salt) {
    if (salt == null || salt.isEmpty()) {
      return false;
    }

    try {
      // Try to decode as base64url
      byte[] decoded = Base64UrlUtils.decode(salt);

      // Check minimum length
      return decoded.length >= MIN_SALT_LENGTH && decoded.length <= MAX_SALT_LENGTH;

    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Validate a salt and throw an exception if invalid.
   *
   * @param salt the salt string to validate
   * @throws IllegalArgumentException if the salt is invalid
   */
  public static void validateSalt(String salt) {
    if (salt == null) {
      throw new IllegalArgumentException("Salt cannot be null");
    }
    if (salt.isEmpty()) {
      throw new IllegalArgumentException("Salt cannot be empty");
    }

    try {
      byte[] decoded = Base64UrlUtils.decode(salt);

      if (decoded.length < MIN_SALT_LENGTH) {
        throw new IllegalArgumentException(
            String.format("Salt is too short. Expected at least %d bytes, but got %d",
                MIN_SALT_LENGTH, decoded.length));
      }
      if (decoded.length > MAX_SALT_LENGTH) {
        throw new IllegalArgumentException(
            String.format("Salt is too long. Expected at most %d bytes, but got %d",
                MAX_SALT_LENGTH, decoded.length));
      }

    } catch (IllegalArgumentException e) {
      throw e; // Re-throw our own exceptions
    } catch (Exception e) {
      throw new IllegalArgumentException("Salt is not valid base64url: " + e.getMessage(), e);
    }
  }

  /**
   * Get the entropy in bits for a salt of the given byte length.
   *
   * @param lengthInBytes the salt length in bytes
   * @return the entropy in bits
   */
  public static int getEntropyBits(int lengthInBytes) {
    return lengthInBytes * 8;
  }

  /**
   * Get the recommended salt length for a given security level.
   *
   * @param securityLevel the desired security level in bits (e.g., 128, 256)
   * @return the recommended salt length in bytes
   * @throws IllegalArgumentException if security level is not supported
   */
  public static int getRecommendedLength(int securityLevel) {
    return switch (securityLevel) {
      case 64 -> 8;   // 64-bit security (minimal)
      case 128 -> 16; // 128-bit security (recommended)
      case 192 -> 24; // 192-bit security
      case 256 -> 32; // 256-bit security (high)
      default -> throw new IllegalArgumentException(
          "Unsupported security level: " + securityLevel +
              ". Supported levels: 64, 128, 192, 256");
    };
  }

  /**
   * Generate a salt with specified security level.
   *
   * @param securityLevel the desired security level in bits
   * @return base64url-encoded salt string
   * @throws IllegalArgumentException if security level is not supported
   */
  public static String generateForSecurityLevel(int securityLevel) {
    int length = getRecommendedLength(securityLevel);
    return generate(length);
  }

  /**
   * Generate a human-readable identifier-style salt (for testing/debugging).
   * This is NOT cryptographically secure and should only be used for testing.
   *
   * @param prefix optional prefix for the salt
   * @return a readable salt string
   */
  public static String generateReadable(String prefix) {
    String timestamp = String.valueOf(System.currentTimeMillis());
    String random = String.valueOf(SECURE_RANDOM.nextInt(10000));

    String readable = (prefix != null ? prefix + "_" : "") +
        timestamp + "_" + random;

    // Encode to make it base64url compatible
    return BASE64_URL_ENCODER.encodeToString(readable.getBytes());
  }

  /**
   * Generate a readable salt without prefix.
   *
   * @return a readable salt string
   */
  public static String generateReadable() {
    return generateReadable(null);
  }
}