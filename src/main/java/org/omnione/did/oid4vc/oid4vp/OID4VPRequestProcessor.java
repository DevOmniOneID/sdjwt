package org.omnione.did.oid4vc.oid4vp;

import org.omnione.did.oid4vc.dcql.DCQLCredentialMatcher;
import org.omnione.did.oid4vc.dcql.DCQLQueryValidator;
import org.omnione.did.sdjwt.core.SDJWT;
import org.omnione.did.oid4vc.dcql.dto.DCQLQuery;

import java.security.PrivateKey;
import java.util.*;

/**
 * OpenID4VP request processor
 * Handles the entire flow from Authorization Request to VP Token generation
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class OID4VPRequestProcessor {

  /**
   * Process OpenID4VP Authorization Request
   *
   * @param request Request to process
   * @return Processing result
   */
  public static OID4VPProcessingResult processAuthorizationRequest(OID4VPRequest request) {
    long startTime = System.currentTimeMillis();

    try {

      // 1. Validate basic request
      OID4VPProcessingResult validationResult = validateRequest(request);
      if (!validationResult.isSuccess()) {
        return validationResult.withProcessingTime(startTime);
      }

      // 2. Validate and process DCQL query
      OID4VPProcessingResult dcqlResult = processDCQLQuery(request);
      if (!dcqlResult.isSuccess()) {
        return dcqlResult.withProcessingTime(startTime);
      }

      // 3. Credential matching
      OID4VPProcessingResult matchingResult = performCredentialMatching(request);
      if (!matchingResult.isSuccess()) {
        return matchingResult.withProcessingTime(startTime);
      }

      // 4. Generate VP Token
      OID4VPProcessingResult vpTokenResult = generateVPTokens(request);

      return vpTokenResult.withProcessingTime(startTime);

    } catch (Exception e) {
      return OID4VPProcessingResult.failure("Request processing failed: " + e.getMessage())
          .withProcessingTime(startTime);
    }
  }

  /**
   * Simplified VP Token generation (single Credential)
   *
   * @param sdJwtVC SD-JWT VC string
   * @param dcqlQuery DCQL query
   * @param credentialId Target Credential ID
   * @param holderPrivateKey Holder's private key
   * @param clientId Verifier Client ID
   * @param nonce Authorization Request nonce
   * @return VP Token generation result
   */
  public static OID4VPProcessingResult createSimpleVPToken(String sdJwtVC,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderPrivateKey,
      String clientId,
      String nonce) {
    try {
      // Validate DCQL
      DCQLQueryValidator.ValidationResult validation = DCQLQueryValidator.validate(dcqlQuery);
      if (!validation.isValid()) {
        return OID4VPProcessingResult.failure("DCQL validation failed: " +
            String.join(", ", validation.getErrors()));
      }

      // Generate VP Token
      String vpToken = OID4VPHandler.createVPTokenFromDCQL(
          sdJwtVC, dcqlQuery, credentialId, holderPrivateKey, clientId, nonce);

      // Wrap in OpenID4VP structure
      String wrappedVpToken = DCQLVPTokenGenerator.wrapSingleCredentialVPToken(credentialId, vpToken);

      OID4VPProcessingResult result = OID4VPProcessingResult.success(wrappedVpToken);

      // Add warnings
      for (String warning : validation.getWarnings()) {
        result.addWarning("DCQL: " + warning);
      }

      return result;

    } catch (Exception e) {
      return OID4VPProcessingResult.failure("VP token creation failed: " + e.getMessage());
    }
  }

  /**
   * Batch VP Token generation (multiple Credentials)
   *
   * @param credentialMap Credential ID and SD-JWT VC map
   * @param dcqlQuery DCQL query
   * @param holderPrivateKey Holder's private key
   * @param clientId Verifier Client ID
   * @param nonce Authorization Request nonce
   * @return VP Token generation result
   */
  public static OID4VPProcessingResult createBatchVPTokens(Map<String, String> credentialMap,
      DCQLQuery dcqlQuery,
      PrivateKey holderPrivateKey,
      String clientId,
      String nonce) {
    try {

      // Validate DCQL
      DCQLQueryValidator.ValidationResult validation = DCQLQueryValidator.validate(dcqlQuery);
      if (!validation.isValid()) {
        return OID4VPProcessingResult.failure("DCQL validation failed");
      }

      // Generate VP Token for each credential
      Map<String, String> vpTokenMap = new HashMap<>();
      List<String> errors = new ArrayList<>();

      for (Map.Entry<String, String> entry : credentialMap.entrySet()) {
        String credentialId = entry.getKey();
        String sdJwtVC = entry.getValue();

        try {
          String vpToken = OID4VPHandler.createVPTokenFromDCQL(
              sdJwtVC, dcqlQuery, credentialId, holderPrivateKey, clientId, nonce);
          vpTokenMap.put(credentialId, vpToken);
        } catch (Exception e) {
          String error = "Failed to create VP token for credential " + credentialId + ": " + e.getMessage();
          errors.add(error);
        }
      }

      if (vpTokenMap.isEmpty()) {
        return OID4VPProcessingResult.failure("No VP tokens were successfully created");
      }

      // Create combined VP Token
      String combinedVpToken = DCQLVPTokenGenerator.combineMultipleVPTokens(vpTokenMap);

      OID4VPProcessingResult result = OID4VPProcessingResult.success(combinedVpToken);
      result.addMetadata("processedCredentials", vpTokenMap.keySet());
      result.addMetadata("totalCredentials", credentialMap.size());
      result.addMetadata("successfulCredentials", vpTokenMap.size());

      // Add errors as warnings
      errors.forEach(result::addWarning);

      return result;

    } catch (Exception e) {
      return OID4VPProcessingResult.failure("Batch VP token creation failed: " + e.getMessage());
    }
  }

  // Private helper methods

  private static OID4VPProcessingResult validateRequest(OID4VPRequest request) {
    if (request == null) {
      return OID4VPProcessingResult.failure("Request is null");
    }

    if (request.getClientId() == null || request.getClientId().trim().isEmpty()) {
      return OID4VPProcessingResult.failure("Client ID is required");
    }

    if (request.getNonce() == null || request.getNonce().trim().isEmpty()) {
      return OID4VPProcessingResult.failure("Nonce is required");
    }

    if (request.getDcqlQuery() == null) {
      return OID4VPProcessingResult.failure("DCQL query is required");
    }

    if (request.getCredentialMap() == null || request.getCredentialMap().isEmpty()) {
      return OID4VPProcessingResult.failure("No credentials available");
    }

    return OID4VPProcessingResult.success("Request validation passed");
  }

  private static OID4VPProcessingResult processDCQLQuery(OID4VPRequest request) {
    DCQLQueryValidator.ValidationResult validation =
        DCQLQueryValidator.validate(request.getDcqlQuery());

    if (!validation.isValid()) {
      return OID4VPProcessingResult.failure(
          "DCQL validation failed: " + String.join(", ", validation.getErrors()));
    }

    OID4VPProcessingResult result = OID4VPProcessingResult.success("DCQL query processed");

    // 경고사항 추가
    for (String warning : validation.getWarnings()) {
      result.addWarning("DCQL: " + warning);
    }

    return result;
  }

  private static OID4VPProcessingResult performCredentialMatching(OID4VPRequest request) {
    try {
      Map<String, SDJWT> sdjwtMap = new HashMap<>();

      // Parse SD-JWT
      for (Map.Entry<String, String> entry : request.getCredentialMap().entrySet()) {
        try {
          SDJWT sdjwt = SDJWT.parse(entry.getValue());
          sdjwtMap.put(entry.getKey(), sdjwt);
        } catch (Exception e) {
        }
      }

      // Credential matching
      Set<String> matchingCredentials = DCQLCredentialMatcher.findMatchingCredentials(
          sdjwtMap, request.getDcqlQuery());

      if (matchingCredentials.isEmpty()) {
        return OID4VPProcessingResult.failure("No credentials match the DCQL requirements");
      }

      OID4VPProcessingResult result = OID4VPProcessingResult.success("Credential matching completed");
      result.addMetadata("matchingCredentials", matchingCredentials);
      result.addMetadata("totalAvailable", sdjwtMap.size());
      result.addMetadata("matchingCount", matchingCredentials.size());

      return result;

    } catch (Exception e) {
      return OID4VPProcessingResult.failure("Credential matching failed: " + e.getMessage());
    }
  }

  private static OID4VPProcessingResult generateVPTokens(OID4VPRequest request) {
    return createBatchVPTokens(
        request.getCredentialMap(),
        request.getDcqlQuery(),
        request.getHolderPrivateKey(),
        request.getClientId(),
        request.getNonce()
    );
  }

  /**
   * OpenID4VP request information
   */
  public static class OID4VPRequest {
    private String clientId;
    private String nonce;
    private DCQLQuery dcqlQuery;
    private Map<String, String> credentialMap;  // credentialId -> SD-JWT VC
    private PrivateKey holderPrivateKey;
    private Map<String, Object> additionalParams;

    // Constructors, getters, and setters
    public OID4VPRequest() {}

    public OID4VPRequest(String clientId, String nonce, DCQLQuery dcqlQuery,
        Map<String, String> credentialMap, PrivateKey holderPrivateKey) {
      this.clientId = clientId;
      this.nonce = nonce;
      this.dcqlQuery = dcqlQuery;
      this.credentialMap = credentialMap;
      this.holderPrivateKey = holderPrivateKey;
    }

    // Getters and Setters
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public DCQLQuery getDcqlQuery() { return dcqlQuery; }
    public void setDcqlQuery(DCQLQuery dcqlQuery) { this.dcqlQuery = dcqlQuery; }

    public Map<String, String> getCredentialMap() { return credentialMap; }
    public void setCredentialMap(Map<String, String> credentialMap) { this.credentialMap = credentialMap; }

    public PrivateKey getHolderPrivateKey() { return holderPrivateKey; }
    public void setHolderPrivateKey(PrivateKey holderPrivateKey) { this.holderPrivateKey = holderPrivateKey; }

    public Map<String, Object> getAdditionalParams() { return additionalParams; }
    public void setAdditionalParams(Map<String, Object> additionalParams) { this.additionalParams = additionalParams; }
  }

  /**
   * OpenID4VP processing result
   */
  public static class OID4VPProcessingResult {
    private boolean success;
    private String message;
    private String vpToken;
    private List<String> warnings = new ArrayList<>();
    private Map<String, Object> metadata = new HashMap<>();
    private long processingTimeMs;

    private OID4VPProcessingResult(boolean success, String message) {
      this.success = success;
      this.message = message;
    }

    public static OID4VPProcessingResult success(String message) {
      return new OID4VPProcessingResult(true, message);
    }

    public static OID4VPProcessingResult failure(String message) {
      return new OID4VPProcessingResult(false, message);
    }

    public OID4VPProcessingResult withVpToken(String vpToken) {
      this.vpToken = vpToken;
      return this;
    }

    public OID4VPProcessingResult addWarning(String warning) {
      warnings.add(warning);
      return this;
    }

    public OID4VPProcessingResult addMetadata(String key, Object value) {
      metadata.put(key, value);
      return this;
    }

    public OID4VPProcessingResult withProcessingTime(long startTimeMs) {
      this.processingTimeMs = System.currentTimeMillis() - startTimeMs;
      return this;
    }

    // Getters
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public String getVpToken() { return vpToken; }
    public List<String> getWarnings() { return warnings; }
    public Map<String, Object> getMetadata() { return metadata; }
    public long getProcessingTimeMs() { return processingTimeMs; }
  }
}