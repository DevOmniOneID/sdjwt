package com.example.oid4vc.sdjwt.oid4vp;

import com.example.oid4vc.sdjwt.dcql.DCQLClaimsExtractor;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.example.oid4vc.sdjwt.exception.SDJWTException;
import lombok.extern.slf4j.Slf4j;

import java.security.PrivateKey;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * SD-JWT VP Token Builder - Fluent API for VP Token creation
 * OpenID4VP 1.0 완전 준수하는 빌더 패턴 제공
 *
 * Usage example:
 * <pre>
 * String vpToken = SDJWTVPTokenBuilder.create()
 *     .withCredential("my_id", sdJwtVc)
 *     .withPrivateKey(holderKey)
 *     .withAudience("verifier_client_id")
 *     .withNonce("transaction_nonce")
 *     .withClaims("name", "age", "address")
 *     .build();
 * </pre>
 *
 * @author OmniOne Open DID
 * @version 2.0
 * @since 1.0
 */
@Slf4j
public class SDJWTVPTokenBuilder {

  private final ObjectMapper objectMapper = new ObjectMapper();
  private String credentialId;
  private String sdJwtVC;
  private PrivateKey holderPrivateKey;
  private String audience;
  private String nonce;
  private Set<String> requestedClaims = new HashSet<>();
  private DCQLQuery dcqlQuery;
  private boolean fullDisclosure = false;
  private boolean minimalDisclosure = false;
  private boolean multipleAllowed = false;

  private SDJWTVPTokenBuilder() {}

  /**
   * Create a new SDJWTVPTokenBuilder instance
   */
  public static SDJWTVPTokenBuilder create() {
    return new SDJWTVPTokenBuilder();
  }

  /**
   * Set the credential ID and SD-JWT VC data
   *
   * @param credentialId Credential identifier for the VP Token
   * @param sdJwtVC SD-JWT VC string
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withCredential(String credentialId, String sdJwtVC) {
    this.credentialId = credentialId;
    this.sdJwtVC = sdJwtVC;
    return this;
  }

  /**
   * Set the holder's private key for key binding JWT
   *
   * @param privateKey Holder's private key
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withPrivateKey(PrivateKey privateKey) {
    this.holderPrivateKey = privateKey;
    return this;
  }

  /**
   * Set the audience (verifier's client ID)
   *
   * @param audience Verifier's client identifier
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withAudience(String audience) {
    this.audience = audience;
    return this;
  }

  /**
   * Set the nonce from the authorization request
   *
   * @param nonce Transaction nonce
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withNonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  /**
   * Add specific claims to be disclosed
   *
   * @param claimNames Claim names to disclose
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withClaims(String... claimNames) {
    for (String claimName : claimNames) {
      this.requestedClaims.add(claimName);
    }
    return this;
  }

  /**
   * Add a set of claims to be disclosed
   *
   * @param claimNames Set of claim names to disclose
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withClaims(Set<String> claimNames) {
    this.requestedClaims.addAll(claimNames);
    return this;
  }

  /**
   * Set DCQL query for automatic claim extraction
   * Claims will be extracted from DCQL if no explicit claims are set
   *
   * @param dcqlQuery DCQL query object
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withDCQL(DCQLQuery dcqlQuery) {
    this.dcqlQuery = dcqlQuery;
    return this;
  }

  /**
   * Enable full disclosure (all available claims)
   *
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withFullDisclosure() {
    this.fullDisclosure = true;
    this.minimalDisclosure = false;
    return this;
  }

  /**
   * Enable minimal disclosure (no selective disclosures)
   *
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder withMinimalDisclosure() {
    this.minimalDisclosure = true;
    this.fullDisclosure = false;
    return this;
  }

  /**
   * Allow multiple presentations in the VP Token
   * This sets the multiple flag according to OpenID4VP 1.0 Section 6.1
   *
   * @return This builder instance
   */
  public SDJWTVPTokenBuilder allowMultiple() {
    this.multipleAllowed = true;
    return this;
  }

  /**
   * Build the VP Token according to OpenID4VP 1.0
   *
   * @return VP Token JSON string
   * @throws IllegalStateException if required parameters are missing
   * @throws RuntimeException if VP Token creation fails
   */
  public String build() {
    validateRequiredParameters();

    try {
      String vpTokenString = createVPTokenString();
      return createVPTokenStructure(vpTokenString);

    } catch (SDJWTException e) {
      log.error("JOSE error during VP Token creation", e);
      throw new RuntimeException("VP Token creation failed due to JOSE error: " + e.getMessage(), e);
    } catch (Exception e) {
      log.error("Failed to build VP Token", e);
      throw new RuntimeException("VP Token creation failed", e);
    }
  }

  /**
   * Build VP Token with detailed result information
   *
   * @return Detailed VP Token creation result
   */
  public VPTokenBuildResult buildWithResult() {
    long startTime = System.currentTimeMillis();

    try {
      validateRequiredParameters();

      Set<String> effectiveClaims = getEffectiveRequestedClaims();
      String vpTokenString = createVPTokenString();
      String vpToken = createVPTokenStructure(vpTokenString);

      long processingTime = System.currentTimeMillis() - startTime;

      return VPTokenBuildResult.builder()
          .vpToken(vpToken)
          .success(true)
          .credentialId(credentialId)
          .requestedClaims(effectiveClaims)
          .processingTimeMs(processingTime)
          .fullDisclosure(fullDisclosure)
          .minimalDisclosure(minimalDisclosure)
          .build();

    } catch (Exception e) {
      long processingTime = System.currentTimeMillis() - startTime;
      log.error("VP Token build failed", e);

      return VPTokenBuildResult.builder()
          .success(false)
          .error(e.getMessage())
          .credentialId(credentialId)
          .processingTimeMs(processingTime)
          .build();
    }
  }

  /**
   * Build multiple VP Tokens with different claim sets
   * Useful for complex DCQL queries with multiple credential sets
   *
   * @param claimSets List of claim sets for different presentations
   * @return VP Token JSON string with multiple presentations
   */
  public String buildMultiple(List<Set<String>> claimSets) {
    validateRequiredParameters();

    try {
      List<String> vpTokenStrings = OID4VPHandler.createMultipleVPTokens(
          sdJwtVC, claimSets, holderPrivateKey, audience, nonce);

      return createMultipleVPTokenStructure(vpTokenStrings);

    } catch (SDJWTException e) {
      log.error("JOSE error during multiple VP Token creation", e);
      throw new RuntimeException("Multiple VP Token creation failed due to JOSE error: " + e.getMessage(), e);
    } catch (Exception e) {
      log.error("Failed to build multiple VP Tokens", e);
      throw new RuntimeException("Multiple VP Token creation failed", e);
    }
  }

  private void validateRequiredParameters() {
    if (credentialId == null || credentialId.trim().isEmpty()) {
      throw new IllegalStateException("Credential ID is required");
    }
    if (sdJwtVC == null || sdJwtVC.trim().isEmpty()) {
      throw new IllegalStateException("SD-JWT VC is required");
    }
    if (holderPrivateKey == null) {
      throw new IllegalStateException("Holder private key is required");
    }
    if (audience == null || audience.trim().isEmpty()) {
      throw new IllegalStateException("Audience (verifier client ID) is required");
    }
    if (nonce == null || nonce.trim().isEmpty()) {
      throw new IllegalStateException("Nonce is required");
    }
  }

  private Set<String> getEffectiveRequestedClaims() {
    if (!requestedClaims.isEmpty()) {
      return requestedClaims;
    }

    if (dcqlQuery != null && credentialId != null) {
      return DCQLClaimsExtractor.extractClaimsForCredential(dcqlQuery, credentialId);
    }

    return new HashSet<>();
  }

  private String createVPTokenString() throws SDJWTException {
    if (fullDisclosure) {
      log.debug("Creating VP token with full disclosure");
      return OID4VPHandler.createFullVPToken(sdJwtVC, holderPrivateKey, audience, nonce);
    } else if (minimalDisclosure) {
      log.debug("Creating VP token with minimal disclosure");
      return OID4VPHandler.createMinimalVPToken(sdJwtVC, holderPrivateKey, audience, nonce);
    } else if (dcqlQuery != null) {
      log.debug("Creating VP token from DCQL query");
      return OID4VPHandler.createVPTokenFromDCQL(
          sdJwtVC, dcqlQuery, credentialId, holderPrivateKey, audience, nonce);
    } else {
      Set<String> effectiveClaims = getEffectiveRequestedClaims();
      log.debug("Creating VP token with {} specific claims", effectiveClaims.size());
      return OID4VPHandler.createVPToken(sdJwtVC, effectiveClaims, holderPrivateKey, audience, nonce);
    }
  }

  private String createVPTokenStructure(String vpTokenString) throws Exception {
    ObjectNode vpToken = objectMapper.createObjectNode();
    ArrayNode presentations = objectMapper.createArrayNode();
    presentations.add(vpTokenString);
    vpToken.set(credentialId, presentations);

    log.info("Created VP Token structure for credential: {}", credentialId);
    return objectMapper.writeValueAsString(vpToken);
  }

  private String createMultipleVPTokenStructure(List<String> vpTokenStrings) throws Exception {
    ObjectNode vpToken = objectMapper.createObjectNode();
    ArrayNode presentations = objectMapper.createArrayNode();

    for (String vpTokenString : vpTokenStrings) {
      presentations.add(vpTokenString);
    }

    vpToken.set(credentialId, presentations);

    log.info("Created multiple VP Token structure with {} presentations for credential: {}",
        vpTokenStrings.size(), credentialId);
    return objectMapper.writeValueAsString(vpToken);
  }

  // Convenience static methods

  /**
   * Create a simple VP Token with basic parameters
   * Convenience method for common use cases
   */
  public static String createSimple(String credentialId, String sdJwtVC,
      PrivateKey holderKey, String audience, String nonce, String... claims) {
    return create()
        .withCredential(credentialId, sdJwtVC)
        .withPrivateKey(holderKey)
        .withAudience(audience)
        .withNonce(nonce)
        .withClaims(claims)
        .build();
  }

  /**
   * Create a VP Token from DCQL query
   * Convenience method for DCQL-based VP token creation
   */
  public static String createFromDCQL(String credentialId, String sdJwtVC,
      DCQLQuery dcqlQuery, PrivateKey holderKey,
      String audience, String nonce) {
    return create()
        .withCredential(credentialId, sdJwtVC)
        .withPrivateKey(holderKey)
        .withAudience(audience)
        .withNonce(nonce)
        .withDCQL(dcqlQuery)
        .build();
  }

  /**
   * Create a full disclosure VP Token
   * Convenience method for full credential disclosure
   */
  public static String createFull(String credentialId, String sdJwtVC,
      PrivateKey holderKey, String audience, String nonce) {
    return create()
        .withCredential(credentialId, sdJwtVC)
        .withPrivateKey(holderKey)
        .withAudience(audience)
        .withNonce(nonce)
        .withFullDisclosure()
        .build();
  }

  /**
   * Create a minimal disclosure VP Token
   * Convenience method for minimal data exposure
   */
  public static String createMinimal(String credentialId, String sdJwtVC,
      PrivateKey holderKey, String audience, String nonce) {
    return create()
        .withCredential(credentialId, sdJwtVC)
        .withPrivateKey(holderKey)
        .withAudience(audience)
        .withNonce(nonce)
        .withMinimalDisclosure()
        .build();
  }

  /**
   * VP Token 빌드 결과 정보
   */
  public static class VPTokenBuildResult {
    private String vpToken;
    private boolean success;
    private String error;
    private String credentialId;
    private Set<String> requestedClaims;
    private long processingTimeMs;
    private boolean fullDisclosure;
    private boolean minimalDisclosure;

    public static VPTokenBuildResultBuilder builder() {
      return new VPTokenBuildResultBuilder();
    }

    // Getters
    public String getVpToken() { return vpToken; }
    public boolean isSuccess() { return success; }
    public String getError() { return error; }
    public String getCredentialId() { return credentialId; }
    public Set<String> getRequestedClaims() { return requestedClaims; }
    public long getProcessingTimeMs() { return processingTimeMs; }
    public boolean isFullDisclosure() { return fullDisclosure; }
    public boolean isMinimalDisclosure() { return minimalDisclosure; }

    public static class VPTokenBuildResultBuilder {
      private String vpToken;
      private boolean success;
      private String error;
      private String credentialId;
      private Set<String> requestedClaims;
      private long processingTimeMs;
      private boolean fullDisclosure;
      private boolean minimalDisclosure;

      public VPTokenBuildResultBuilder vpToken(String vpToken) { this.vpToken = vpToken; return this; }
      public VPTokenBuildResultBuilder success(boolean success) { this.success = success; return this; }
      public VPTokenBuildResultBuilder error(String error) { this.error = error; return this; }
      public VPTokenBuildResultBuilder credentialId(String credentialId) { this.credentialId = credentialId; return this; }
      public VPTokenBuildResultBuilder requestedClaims(Set<String> claims) { this.requestedClaims = claims; return this; }
      public VPTokenBuildResultBuilder processingTimeMs(long time) { this.processingTimeMs = time; return this; }
      public VPTokenBuildResultBuilder fullDisclosure(boolean full) { this.fullDisclosure = full; return this; }
      public VPTokenBuildResultBuilder minimalDisclosure(boolean minimal) { this.minimalDisclosure = minimal; return this; }

      public VPTokenBuildResult build() {
        VPTokenBuildResult result = new VPTokenBuildResult();
        result.vpToken = this.vpToken;
        result.success = this.success;
        result.error = this.error;
        result.credentialId = this.credentialId;
        result.requestedClaims = this.requestedClaims;
        result.processingTimeMs = this.processingTimeMs;
        result.fullDisclosure = this.fullDisclosure;
        result.minimalDisclosure = this.minimalDisclosure;
        return result;
      }
    }
  }
}