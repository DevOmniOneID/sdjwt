package org.omnione.did.oid4vc.core.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.Map;

/**
 * Simple JWT decoder for test purposes to reduce external library dependencies
 * This is a basic implementation for JWT parsing without signature verification
 */
public class SimpleJWTDecoder {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * Simple JWT token representation
   */
  public static class SimpleJWT {
    private final JsonNode header;
    private final JsonNode payload;
    private final String signature;

    public SimpleJWT(JsonNode header, JsonNode payload, String signature) {
      this.header = header;
      this.payload = payload;
      this.signature = signature;
    }

    public JsonNode getHeader() {
      return header;
    }

    public JsonNode getPayload() {
      return payload;
    }

    public String getSignature() {
      return signature;
    }

    /**
     * Get payload as Map for easier access
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getPayloadAsMap() {
      try {
        return objectMapper.convertValue(payload, Map.class);
      } catch (Exception e) {
        throw new RuntimeException("Failed to convert payload to Map", e);
      }
    }

    /**
     * Get a specific claim from payload
     */
    public Object getClaim(String claimName) {
      return payload.get(claimName);
    }

    /**
     * Get a specific claim as String
     */
    public String getStringClaim(String claimName) {
      JsonNode claim = payload.get(claimName);
      return claim != null ? claim.asText() : null;
    }

    /**
     * Get a specific claim as Long
     */
    public Long getLongClaim(String claimName) {
      JsonNode claim = payload.get(claimName);
      return claim != null ? claim.asLong() : null;
    }

    @Override
    public String toString() {
      return "SimpleJWT{" +
          "header=" + header +
          ", payload=" + payload +
          ", signature='" + signature + '\'' +
          '}';
    }
  }

  /**
   * Parse JWT string into SimpleJWT object
   * This method only decodes the JWT without verifying signature
   *
   * @param jwtString JWT token string
   * @return SimpleJWT object
   * @throws RuntimeException if JWT parsing fails
   */
  public static SimpleJWT parse(String jwtString) {
    if (jwtString == null || jwtString.trim().isEmpty()) {
      throw new IllegalArgumentException("JWT string cannot be null or empty");
    }

    String[] parts = jwtString.split("\\.");
    if (parts.length != 3) {
      throw new IllegalArgumentException("Invalid JWT format: expected 3 parts separated by dots");
    }

    try {
      // Decode header
      String headerJson = base64UrlDecode(parts[0]);
      JsonNode header = objectMapper.readTree(headerJson);

      // Decode payload
      String payloadJson = base64UrlDecode(parts[1]);
      JsonNode payload = objectMapper.readTree(payloadJson);

      // Keep signature as-is (base64url encoded)
      String signature = parts[2];

      return new SimpleJWT(header, payload, signature);

    } catch (Exception e) {
      throw new RuntimeException("Failed to parse JWT: " + e.getMessage(), e);
    }
  }

  /**
   * Base64URL decode according to RFC 7515
   */
  private static String base64UrlDecode(String base64Url) {
    try {
      // Base64URL decoder handles padding automatically
      byte[] decoded = Base64.getUrlDecoder().decode(base64Url);
      return new String(decoded, "UTF-8");
    } catch (Exception e) {
      throw new RuntimeException("Failed to decode Base64URL: " + e.getMessage(), e);
    }
  }

  /**
   * Check if a string looks like a JWT token
   */
  public static boolean isJWTFormat(String input) {
    if (input == null || input.trim().isEmpty()) {
      return false;
    }

    // JWT format has exactly 3 parts separated by dots
    String[] parts = input.trim().split("\\.");
    if (parts.length != 3) {
      return false;
    }

    try {
      // Try to decode the first part as JWT header
      JsonNode header = objectMapper.readTree(base64UrlDecode(parts[0]));
      return header.has("alg") && header.has("typ");
    } catch (Exception e) {
      return false;
    }
  }
}