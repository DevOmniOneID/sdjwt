package com.example.oid4vc.sdjwt.oid4vp;

import com.example.oid4vc.sdjwt.dcql.DCQLCredentialMatcher;
import com.example.oid4vc.sdjwt.dcql.DCQLQueryValidator;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import lombok.extern.slf4j.Slf4j;

import java.security.PrivateKey;
import java.util.*;

/**
 * OpenID4VP 요청 처리기
 * Authorization Request부터 VP Token 생성까지의 전체 플로우를 처리
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
@Slf4j
public class OID4VPRequestProcessor {

  /**
   * OpenID4VP Authorization Request 처리
   *
   * @param request 처리할 요청
   * @return 처리 결과
   */
  public static OID4VPProcessingResult processAuthorizationRequest(OID4VPRequest request) {
    long startTime = System.currentTimeMillis();

    try {
      log.info("Processing OpenID4VP authorization request for client: {}", request.getClientId());

      // 1. 기본 요청 유효성 검증
      OID4VPProcessingResult validationResult = validateRequest(request);
      if (!validationResult.isSuccess()) {
        return validationResult.withProcessingTime(startTime);
      }

      // 2. DCQL 쿼리 검증 및 처리
      OID4VPProcessingResult dcqlResult = processDCQLQuery(request);
      if (!dcqlResult.isSuccess()) {
        return dcqlResult.withProcessingTime(startTime);
      }

      // 3. Credential 매칭
      OID4VPProcessingResult matchingResult = performCredentialMatching(request);
      if (!matchingResult.isSuccess()) {
        return matchingResult.withProcessingTime(startTime);
      }

      // 4. VP Token 생성
      OID4VPProcessingResult vpTokenResult = generateVPTokens(request);

      return vpTokenResult.withProcessingTime(startTime);

    } catch (Exception e) {
      log.error("Failed to process OpenID4VP authorization request", e);
      return OID4VPProcessingResult.failure("Request processing failed: " + e.getMessage())
          .withProcessingTime(startTime);
    }
  }

  /**
   * 단순화된 VP Token 생성 (단일 Credential)
   *
   * @param sdJwtVC SD-JWT VC 문자열
   * @param dcqlQuery DCQL 쿼리
   * @param credentialId 대상 Credential ID
   * @param holderPrivateKey Holder 개인키
   * @param clientId Verifier Client ID
   * @param nonce Authorization Request nonce
   * @return VP Token 생성 결과
   */
  public static OID4VPProcessingResult createSimpleVPToken(String sdJwtVC,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderPrivateKey,
      String clientId,
      String nonce) {
    try {
      // DCQL 검증
      DCQLQueryValidator.ValidationResult validation = DCQLQueryValidator.validate(dcqlQuery);
      if (!validation.isValid()) {
        return OID4VPProcessingResult.failure("DCQL validation failed: " +
            String.join(", ", validation.getErrors()));
      }

      // VP Token 생성
      String vpToken = OID4VPHandler.createVPTokenFromDCQL(
          sdJwtVC, dcqlQuery, credentialId, holderPrivateKey, clientId, nonce);

      // OpenID4VP 구조로 래핑
      String wrappedVpToken = DCQLVPTokenGenerator.wrapSingleCredentialVPToken(credentialId, vpToken);

      OID4VPProcessingResult result = OID4VPProcessingResult.success(wrappedVpToken);

      // 경고사항 추가
      for (String warning : validation.getWarnings()) {
        result.addWarning("DCQL: " + warning);
      }

      return result;

    } catch (Exception e) {
      log.error("Failed to create simple VP token", e);
      return OID4VPProcessingResult.failure("VP token creation failed: " + e.getMessage());
    }
  }

  /**
   * 배치 VP Token 생성 (여러 Credential)
   *
   * @param credentialMap Credential ID와 SD-JWT VC 맵
   * @param dcqlQuery DCQL 쿼리
   * @param holderPrivateKey Holder 개인키
   * @param clientId Verifier Client ID
   * @param nonce Authorization Request nonce
   * @return VP Token 생성 결과
   */
  public static OID4VPProcessingResult createBatchVPTokens(Map<String, String> credentialMap,
      DCQLQuery dcqlQuery,
      PrivateKey holderPrivateKey,
      String clientId,
      String nonce) {
    try {
      log.info("Creating batch VP tokens for {} credentials", credentialMap.size());

      // DCQL 검증
      DCQLQueryValidator.ValidationResult validation = DCQLQueryValidator.validate(dcqlQuery);
      if (!validation.isValid()) {
        return OID4VPProcessingResult.failure("DCQL validation failed");
      }

      // Credential별 VP Token 생성
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
          log.error(error, e);
        }
      }

      if (vpTokenMap.isEmpty()) {
        return OID4VPProcessingResult.failure("No VP tokens were successfully created");
      }

      // 통합 VP Token 생성
      String combinedVpToken = DCQLVPTokenGenerator.combineMultipleVPTokens(vpTokenMap);

      OID4VPProcessingResult result = OID4VPProcessingResult.success(combinedVpToken);
      result.addMetadata("processedCredentials", vpTokenMap.keySet());
      result.addMetadata("totalCredentials", credentialMap.size());
      result.addMetadata("successfulCredentials", vpTokenMap.size());

      // 에러들을 경고로 추가
      errors.forEach(result::addWarning);

      return result;

    } catch (Exception e) {
      log.error("Failed to create batch VP tokens", e);
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

      // SD-JWT 파싱
      for (Map.Entry<String, String> entry : request.getCredentialMap().entrySet()) {
        try {
          SDJWT sdjwt = SDJWT.parse(entry.getValue());
          sdjwtMap.put(entry.getKey(), sdjwt);
        } catch (Exception e) {
          log.warn("Failed to parse SD-JWT for credential {}: {}", entry.getKey(), e.getMessage());
        }
      }

      // Credential 매칭
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
      log.error("Credential matching failed", e);
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
   * OpenID4VP 요청 정보
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
   * OpenID4VP 처리 결과
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