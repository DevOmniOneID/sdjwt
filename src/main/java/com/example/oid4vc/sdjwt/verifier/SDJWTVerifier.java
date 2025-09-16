package com.example.oid4vc.sdjwt.verifier;

import com.example.oid4vc.sdjwt.core.Disclosure;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.exception.SDJWTException;
import com.example.oid4vc.sdjwt.util.Base64UrlUtils;
import com.example.oid4vc.sdjwt.util.HashUtils;
import com.example.oid4vc.sdjwt.validation.SDJWTValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.example.oid4vc.sdjwt.exception.SDJWTException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;

/**
 * SDJWTVerifier provides comprehensive verification of SD-JWTs including
 * JWT signature verification and disclosure validation.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWTVerifier {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final PublicKey publicKey;
  private final SDJWTValidator validator;
  private boolean requireKeyBinding;
  private PublicKey holderPublicKey;

  /**
   * Create a new SDJWTVerifier with the issuer's public key.
   */
  public SDJWTVerifier(PublicKey publicKey) {
    if (publicKey == null) {
      throw new IllegalArgumentException("Public key cannot be null");
    }
    this.publicKey = publicKey;
    this.validator = new SDJWTValidator();
    this.requireKeyBinding = false;
  }

  /**
   * Create a new SDJWTVerifier with both issuer and holder public keys.
   */
  public SDJWTVerifier(PublicKey issuerPublicKey, PublicKey holderPublicKey) {
    this(issuerPublicKey);
    this.holderPublicKey = holderPublicKey;
    this.requireKeyBinding = true;
  }

  /**
   * Set whether key binding JWT verification is required.
   */
  public SDJWTVerifier requireKeyBinding(boolean require) {
    this.requireKeyBinding = require;
    return this;
  }

  /**
   * Set the holder's public key for key binding verification.
   */
  public SDJWTVerifier holderPublicKey(PublicKey holderPublicKey) {
    this.holderPublicKey = holderPublicKey;
    return this;
  }

  /**
   * Verify an SD-JWT and return the verified claims.
   */
  public SDJWTClaimsSet verify(String sdJwtString) throws SDJWTException {
    return verify(sdJwtString, null, null);
  }

  /**
   * Verify an SD-JWT with audience and nonce validation.
   */
  public SDJWTClaimsSet verify(String sdJwtString, String expectedAudience, String expectedNonce) throws SDJWTException {
    try {
      // 1. Parse SD-JWT
      SDJWT sdJwt = SDJWT.parse(sdJwtString);

      // 2. Validate SD-JWT structure
      SDJWTValidator.ValidationResult structureResult = validator.validate(sdJwt);
      if (!structureResult.isValid()) {
        throw new SDJWTException("SD-JWT structure validation failed: " + structureResult.getErrors());
      }

      // 3. Verify credential JWT signature
      SignedJWT credentialJwt = SignedJWT.parse(sdJwt.getCredentialJwt());
      if (!verifyJWTSignature(credentialJwt, publicKey)) {
        throw new SDJWTException("Credential JWT signature verification failed");
      }

      // 4. Verify key binding JWT if present or required
      if (sdJwt.hasKeyBindingJwt() || requireKeyBinding) {
        if (!sdJwt.hasKeyBindingJwt() && requireKeyBinding) {
          throw new SDJWTException("Key binding JWT is required but not present");
        }

        if (sdJwt.hasKeyBindingJwt()) {
          verifyKeyBindingJWT(sdJwt.getKeyBindingJwt(), expectedAudience, expectedNonce);
        }
      }

      // 5. Verify disclosure integrity
      verifyDisclosureIntegrity(sdJwt);

      // 6. Build verified claims set
      return buildClaimsSet(sdJwt);

    } catch (ParseException e) {
      throw new SDJWTException("Failed to parse SD-JWT", e);
    } catch (Exception e) {
      throw new SDJWTException("SD-JWT verification failed", e);
    }
  }

  /**
   * Verify JWT signature using the appropriate verifier.
   */
  private boolean verifyJWTSignature(SignedJWT jwt, PublicKey publicKey) throws SDJWTException {
    try {
      JWSVerifier verifier;

      if (publicKey instanceof RSAPublicKey) {
        verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
      } else if (publicKey instanceof ECPublicKey) {
        verifier = new ECDSAVerifier((ECPublicKey) publicKey);
      } else {
        throw new IllegalArgumentException("Unsupported public key type: " + publicKey.getClass());
      }

      return jwt.verify(verifier);
    } catch (JOSEException e) {
      throw new SDJWTException("Failed to verify JWT signature", e);
    }
  }

  /**
   * Verify key binding JWT.
   */
  private void verifyKeyBindingJWT(String keyBindingJwt, String expectedAudience, String expectedNonce) throws SDJWTException {
    try {
      SignedJWT kbJwt = SignedJWT.parse(keyBindingJwt);

      // Verify signature with holder's public key
      PublicKey kbPublicKey = holderPublicKey != null ? holderPublicKey : extractHolderPublicKey();
      if (kbPublicKey == null) {
        throw new SDJWTException("No holder public key available for key binding verification");
      }

      if (!verifyJWTSignature(kbJwt, kbPublicKey)) {
        throw new SDJWTException("Key binding JWT signature verification failed");
      }

      // Verify claims
      Map<String, Object> kbClaims = kbJwt.getJWTClaimsSet().getClaims();

      if (expectedAudience != null) {
        // Handle both string and list audience values
        Object aud = kbClaims.get("aud");
        boolean audienceMatches = false;
        
        if (aud instanceof String) {
          audienceMatches = expectedAudience.equals(aud);
        } else if (aud instanceof List) {
          List<?> audList = (List<?>) aud;
          audienceMatches = audList.contains(expectedAudience);
        }
        
        if (!audienceMatches) {
          throw new SDJWTException("Key binding JWT audience mismatch. Expected: " + expectedAudience + ", Got: " + aud);
        }
      }

      if (expectedNonce != null) {
        Object nonce = kbClaims.get("nonce");
        if (!expectedNonce.equals(nonce)) {
          throw new SDJWTException("Key binding JWT nonce mismatch. Expected: " + expectedNonce + ", Got: " + nonce);
        }
      }

    } catch (ParseException e) {
      throw new SDJWTException("Failed to parse key binding JWT", e);
    } catch (Exception e) {
      throw new SDJWTException("Key binding JWT verification failed", e);
    }
  }

  /**
   * Extract holder public key from the credential JWT's cnf claim.
   */
  private PublicKey extractHolderPublicKey() throws SDJWTException {
    // This would need to be implemented based on the cnf claim format
    // For now, we'll rely on the explicitly set holder public key
    return holderPublicKey;
  }

  /**
   * Verify that all disclosures match their digests in the credential JWT.
   */
  private void verifyDisclosureIntegrity(SDJWT sdJwt) throws SDJWTException {
    try {
      SignedJWT credentialJwt = SignedJWT.parse(sdJwt.getCredentialJwt());
      Map<String, Object> payload = credentialJwt.getJWTClaimsSet().getClaims();

      // Extract _sd array and hash algorithm
      List<String> sdArray = extractSDArray(payload);
      String hashAlgorithm = extractHashAlgorithm(payload);

      // Verify each disclosure
      for (Disclosure disclosure : sdJwt.getDisclosures()) {
        String computedDigest = disclosure.digest(hashAlgorithm);

        if (!sdArray.contains(computedDigest)) {
          throw new SDJWTException("Disclosure digest not found in _sd array: " + computedDigest);
        }
      }

    } catch (ParseException e) {
      throw new SDJWTException("Failed to parse credential JWT for disclosure verification", e);
    }
  }

  /**
   * Extract _sd array from JWT payload.
   */
  @SuppressWarnings("unchecked")
  private List<String> extractSDArray(Map<String, Object> payload) {
    Object sdObj = payload.get("_sd");
    if (sdObj instanceof List) {
      return (List<String>) sdObj;
    }
    return new ArrayList<>();
  }

  /**
   * Extract hash algorithm from JWT payload.
   */
  private String extractHashAlgorithm(Map<String, Object> payload) {
    Object alg = payload.get("_sd_alg");
    return alg != null ? alg.toString() : HashUtils.getDefaultHashAlgorithm();
  }

  /**
   * Build the final claims set with disclosed claims.
   */
  private SDJWTClaimsSet buildClaimsSet(SDJWT sdJwt) throws SDJWTException {
    try {
      SignedJWT credentialJwt = SignedJWT.parse(sdJwt.getCredentialJwt());
      Map<String, Object> baseClaims = new LinkedHashMap<>(credentialJwt.getJWTClaimsSet().getClaims());

      // Remove SD-JWT specific claims
      baseClaims.remove("_sd");
      baseClaims.remove("_sd_alg");

      // Add disclosed claims
      for (Disclosure disclosure : sdJwt.getDisclosures()) {
        if (!disclosure.isArrayElement()) {
          baseClaims.put(disclosure.getClaimName(), disclosure.getClaimValue());
        }
      }

      return new SDJWTClaimsSet(baseClaims, sdJwt.getDisclosures());

    } catch (ParseException e) {
      throw new SDJWTException("Failed to build claims set", e);
    }
  }

  /**
   * Represents the verified claims from an SD-JWT.
   */
  public static class SDJWTClaimsSet {
    private final Map<String, Object> claims;
    private final List<Disclosure> disclosures;

    public SDJWTClaimsSet(Map<String, Object> claims, List<Disclosure> disclosures) {
      this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
      this.disclosures = Collections.unmodifiableList(new ArrayList<>(disclosures));
    }

    public Map<String, Object> getClaims() {
      return claims;
    }

    public List<Disclosure> getDisclosures() {
      return disclosures;
    }

    public Object getClaim(String name) {
      return claims.get(name);
    }

    public String getStringClaim(String name) {
      Object value = getClaim(name);
      return value != null ? value.toString() : null;
    }

    public Long getLongClaim(String name) {
      Object value = getClaim(name);
      if (value instanceof Number) {
        return ((Number) value).longValue();
      }
      return null;
    }

    public Boolean getBooleanClaim(String name) {
      Object value = getClaim(name);
      if (value instanceof Boolean) {
        return (Boolean) value;
      }
      return null;
    }

    public Set<String> getClaimNames() {
      return claims.keySet();
    }

    public boolean hasClaim(String name) {
      return claims.containsKey(name);
    }

    @Override
    public String toString() {
      return "SDJWTClaimsSet{" +
          "claims=" + claims +
          ", disclosureCount=" + disclosures.size() +
          '}';
    }
  }
}