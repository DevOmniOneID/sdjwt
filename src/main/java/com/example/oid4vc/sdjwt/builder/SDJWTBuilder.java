package com.example.oid4vc.sdjwt.builder;

import com.example.oid4vc.sdjwt.core.Disclosure;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.core.SDObjectBuilder;
import com.example.oid4vc.sdjwt.util.HashUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Function;

/**
 * SDJWTBuilder provides a convenient builder pattern for creating SD-JWTs.
 * This class follows the Authlete SDK design pattern for easy migration.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWTBuilder {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final Map<String, Object> claims;
  private final List<Disclosure> disclosures;
  private String hashAlgorithm;
  private boolean includeHashAlgorithm;
  private int decoyCount;

  /**
   * Create a new SDJWTBuilder with default settings.
   */
  public SDJWTBuilder() {
    this.claims = new LinkedHashMap<>();
    this.disclosures = new ArrayList<>();
    this.hashAlgorithm = HashUtils.getDefaultHashAlgorithm();
    this.includeHashAlgorithm = false;
    this.decoyCount = 0;
  }

  /**
   * Create a new SDJWTBuilder with specified hash algorithm.
   */
  public SDJWTBuilder(String hashAlgorithm) {
    this();
    this.hashAlgorithm = hashAlgorithm;
  }

  /**
   * Add a regular (non-selectively-disclosable) claim.
   */
  public SDJWTBuilder claim(String name, Object value) {
    if (name == null || name.trim().isEmpty()) {
      throw new IllegalArgumentException("Claim name cannot be null or empty");
    }
    claims.put(name, value);
    return this;
  }

  /**
   * Add multiple regular claims from a Map.
   */
  public SDJWTBuilder claims(Map<String, Object> claims) {
    if (claims != null) {
      claims.forEach(this::claim);
    }
    return this;
  }

  /**
   * Add a selectively-disclosable claim.
   */
  public SDJWTBuilder selectivelyDisclosableClaim(String name, Object value) {
    if (name == null || name.trim().isEmpty()) {
      throw new IllegalArgumentException("Claim name cannot be null or empty");
    }
    Disclosure disclosure = Disclosure.forObjectProperty(name, value);
    disclosures.add(disclosure);
    return this;
  }

  /**
   * Add a selectively-disclosable claim with explicit salt.
   */
  public SDJWTBuilder selectivelyDisclosableClaim(String salt, String name, Object value) {
    if (name == null || name.trim().isEmpty()) {
      throw new IllegalArgumentException("Claim name cannot be null or empty");
    }
    Disclosure disclosure = new Disclosure(salt, name, value);
    disclosures.add(disclosure);
    return this;
  }

  /**
   * Add multiple selectively-disclosable claims.
   */
  public SDJWTBuilder selectivelyDisclosableClaims(Map<String, Object> claims) {
    if (claims != null) {
      claims.forEach(this::selectivelyDisclosableClaim);
    }
    return this;
  }

  /**
   * Add a Disclosure directly.
   */
  public SDJWTBuilder disclosure(Disclosure disclosure) {
    if (disclosure == null) {
      throw new IllegalArgumentException("Disclosure cannot be null");
    }
    if (disclosure.isArrayElement()) {
      throw new IllegalArgumentException("Array element disclosures are not supported in this context");
    }
    disclosures.add(disclosure);
    return this;
  }

  /**
   * Set the hash algorithm to use for digest computation.
   */
  public SDJWTBuilder hashAlgorithm(String hashAlgorithm) {
    if (!HashUtils.isSupportedHashAlgorithm(hashAlgorithm)) {
      throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
    }
    this.hashAlgorithm = hashAlgorithm;
    return this;
  }

  /**
   * Include the hash algorithm in the resulting JWT payload.
   */
  public SDJWTBuilder includeHashAlgorithm(boolean include) {
    this.includeHashAlgorithm = include;
    return this;
  }

  /**
   * Add decoy digests to the _sd array.
   */
  public SDJWTBuilder decoyDigests(int count) {
    if (count < 0) {
      throw new IllegalArgumentException("Decoy count cannot be negative");
    }
    this.decoyCount = count;
    return this;
  }

  /**
   * Add standard JWT claims for convenience.
   */
  public SDJWTBuilder issuer(String issuer) {
    return claim("iss", issuer);
  }

  public SDJWTBuilder subject(String subject) {
    return claim("sub", subject);
  }

  public SDJWTBuilder audience(String audience) {
    return claim("aud", audience);
  }

  public SDJWTBuilder issuedAtNow() {
    return claim("iat", Instant.now().getEpochSecond());
  }

  public SDJWTBuilder issuedAt(Instant issuedAt) {
    return claim("iat", issuedAt.getEpochSecond());
  }

  public SDJWTBuilder expirationTime(Instant expirationTime) {
    return claim("exp", expirationTime.getEpochSecond());
  }

  public SDJWTBuilder expiresIn(long amount, ChronoUnit unit) {
    Instant exp = Instant.now().plus(amount, unit);
    return claim("exp", exp.getEpochSecond());
  }

  public SDJWTBuilder notBefore(Instant notBefore) {
    return claim("nbf", notBefore.getEpochSecond());
  }

  public SDJWTBuilder jwtId(String jwtId) {
    return claim("jti", jwtId);
  }

  public SDJWTBuilder verifiableCredentialType(String vct) {
    return claim("vct", vct);
  }

  public SDJWTBuilder confirmation(Map<String, Object> cnf) {
    return claim("cnf", cnf);
  }

  /**
   * Build the SD-JWT using the provided JWT signer function.
   */
  public SDJWT build(Function<String, String> jwtSigner) {
    if (jwtSigner == null) {
      throw new IllegalArgumentException("JWT signer function cannot be null");
    }

    try {
      SDObjectBuilder builder = new SDObjectBuilder(hashAlgorithm);

      claims.forEach(builder::putClaim);
      disclosures.forEach(builder::putSDClaim);

      if (decoyCount > 0) {
        builder.putDecoyDigests(decoyCount);
      }

      Map<String, Object> payload = builder.build(includeHashAlgorithm);
      String payloadJson = OBJECT_MAPPER.writeValueAsString(payload);
      String credentialJwt = jwtSigner.apply(payloadJson);

      return new SDJWT(credentialJwt, disclosures);

    } catch (Exception e) {
      throw new RuntimeException("Failed to build SD-JWT", e);
    }
  }

  /**
   * Build the payload without signing.
   */
  public Map<String, Object> buildPayload() {
    SDObjectBuilder builder = new SDObjectBuilder(hashAlgorithm);

    claims.forEach(builder::putClaim);
    disclosures.forEach(builder::putSDClaim);

    if (decoyCount > 0) {
      builder.putDecoyDigests(decoyCount);
    }

    return builder.build(includeHashAlgorithm);
  }

  public List<Disclosure> getDisclosures() {
    return Collections.unmodifiableList(disclosures);
  }

  public Map<String, Object> getClaims() {
    return Collections.unmodifiableMap(claims);
  }

  public String getHashAlgorithm() {
    return hashAlgorithm;
  }
}