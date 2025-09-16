package com.example.oid4vc.sdjwt.keybinding;

import com.example.oid4vc.sdjwt.exception.SDJWTException;
import com.example.oid4vc.sdjwt.jwt.JWSSigner;
import com.example.oid4vc.sdjwt.jwt.SignedJWT;
import com.example.oid4vc.sdjwt.jwt.crypto.ECDSASigner;
import com.example.oid4vc.sdjwt.jwt.crypto.RSASSASigner;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * KeyBindingJWTBuilder creates Key Binding JWTs for SD-JWT presentations.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class KeyBindingJWTBuilder {

  private final PrivateKey holderKey;
  private String audience;
  private String nonce;
  private Instant issuedAt;
  private final Map<String, Object> additionalClaims;

  /**
   * Create a new KeyBindingJWTBuilder.
   */
  public KeyBindingJWTBuilder(PrivateKey holderKey) {
    if (holderKey == null) {
      throw new IllegalArgumentException("Holder private key cannot be null");
    }
    this.holderKey = holderKey;
    this.additionalClaims = new HashMap<>();
    this.issuedAt = Instant.now();
  }

  /**
   * Set the audience claim.
   */
  public KeyBindingJWTBuilder audience(String audience) {
    this.audience = audience;
    return this;
  }

  /**
   * Set the nonce claim.
   */
  public KeyBindingJWTBuilder nonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  /**
   * Set the issued at time.
   */
  public KeyBindingJWTBuilder issuedAt(Instant issuedAt) {
    this.issuedAt = issuedAt;
    return this;
  }

  /**
   * Add an additional claim.
   */
  public KeyBindingJWTBuilder claim(String name, Object value) {
    additionalClaims.put(name, value);
    return this;
  }

  /**
   * Build and sign the Key Binding JWT.
   */
  public String build() throws SDJWTException {
    try {
      // Determine algorithm based on key type
      String algorithm;
      JWSSigner signer;

      if (holderKey instanceof RSAPrivateKey) {
        algorithm = "RS256";
        signer = new RSASSASigner((RSAPrivateKey) holderKey);
      } else if (holderKey instanceof ECPrivateKey) {
        algorithm = "ES256";
        signer = new ECDSASigner((ECPrivateKey) holderKey);
      } else {
        throw new IllegalArgumentException("Unsupported private key type: " + holderKey.getClass());
      }

      // Create header
      Map<String, Object> header = new HashMap<>();
      header.put("alg", algorithm);
      header.put("typ", "kb+jwt");

      // Create claims
      Map<String, Object> claims = new HashMap<>();

      if (audience != null) {
        claims.put("aud", audience);
      }

      if (nonce != null) {
        claims.put("nonce", nonce);
      }

      if (issuedAt != null) {
        claims.put("iat", issuedAt.getEpochSecond());
      }

      // Add additional claims
      claims.putAll(additionalClaims);

      // Create and sign JWT
      SignedJWT signedJWT = new SignedJWT(header, claims);
      signedJWT.sign(signer);

      return signedJWT.serialize();
    } catch (Exception e) {
      throw new SDJWTException("Failed to create key binding JWT", e);
    }
  }

  /**
   * Static helper method to create a Key Binding JWT (backward compatibility).
   */
  public static String createKeyBindingJWT(PrivateKey holderKey, String audience, String nonce) throws SDJWTException {
    return new KeyBindingJWTBuilder(holderKey)
        .audience(audience)
        .nonce(nonce)
        .build();
  }

  /**
   * Static helper method to create a Key Binding JWT with sd_hash (IETF SD-JWT compliant).
   *
   * @param holderKey Holder's private key for signing
   * @param audience Verifier's identifier (aud claim)
   * @param nonce Unique nonce for replay protection
   * @param sdJwtString SD-JWT string (without Key Binding JWT) for hash calculation
   * @return Serialized Key Binding JWT with sd_hash claim
   * @throws SDJWTException if JWT creation or signing fails
   */
  public static String createKeyBindingJWT(PrivateKey holderKey, String audience, String nonce, String sdJwtString) throws SDJWTException {
    String sdHash = calculateSdHash(sdJwtString);

    return new KeyBindingJWTBuilder(holderKey)
        .audience(audience)
        .nonce(nonce)
        .claim("sd_hash", sdHash)
        .build();
  }

  /**
   * Calculate SHA-256 hash of SD-JWT string for sd_hash claim.
   * According to IETF SD-JWT specification, this ensures the Key Binding JWT
   * is cryptographically bound to the specific SD-JWT presentation.
   *
   * @param sdJwtString SD-JWT string (credential + disclosures, ending with ~)
   * @return Base64URL-encoded SHA-256 hash
   */
  private static String calculateSdHash(String sdJwtString) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(sdJwtString.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }
  }
}
