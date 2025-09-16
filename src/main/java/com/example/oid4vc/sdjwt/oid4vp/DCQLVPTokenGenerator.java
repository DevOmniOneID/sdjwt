package com.example.oid4vc.sdjwt.oid4vp;

import com.example.oid4vc.sdjwt.dcql.DCQLClaimsExtractor;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.example.oid4vc.sdjwt.exception.SDJWTException;

import java.security.PrivateKey;
import java.util.*;

/**
 * DCQL 쿼리 기반 VP Token 생성 통합 인터페이스
 * OpenID4VP 1.0 Section 8.1에 완전히 부합하는 VP Token 구조 생성
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLVPTokenGenerator {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * DCQL 쿼리에서 직접 VP Token 생성
   *
   * @param credentialData SD-JWT VC 문자열
   * @param dcqlQuery DCQL 쿼리
   * @param credentialId 대상 credential ID
   * @param holderKey Holder 개인키
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return OpenID4VP 1.0 규격의 VP Token JSON
   */
  public static String generateFromDCQL(String credentialData,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {

      // DCQL에서 요청된 클레임 추출
      Set<String> requestedClaims = DCQLClaimsExtractor.extractClaimsForCredential(dcqlQuery, credentialId);

      // VP Token 생성
      String vpTokenString = OID4VPHandler.createVPTokenFromDCQL(
          credentialData, dcqlQuery, credentialId, holderKey, audience, nonce);

      // OpenID4VP 구조로 래핑
      return wrapSingleCredentialVPToken(credentialId, vpTokenString);

    } catch (SDJWTException e) {
      throw new RuntimeException("Key binding JWT creation failed: " + e.getMessage(), e);
    } catch (Exception e) {
      throw new RuntimeException("DCQL VP token generation failed", e);
    }
  }

  /**
   * 여러 Credential에 대한 VP Token 생성
   *
   * @param credentials Credential ID와 SD-JWT VC 맵
   * @param dcqlQuery DCQL 쿼리
   * @param holderKey Holder 개인키
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return 통합 VP Token JSON
   */
  public static String generateMultipleFromDCQL(Map<String, String> credentials,
      DCQLQuery dcqlQuery,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {

      Map<String, String> vpTokenMap = new HashMap<>();

      for (Map.Entry<String, String> entry : credentials.entrySet()) {
        String credentialId = entry.getKey();
        String sdJwtVC = entry.getValue();

        try {
          String vpTokenString = OID4VPHandler.createVPTokenFromDCQL(
              sdJwtVC, dcqlQuery, credentialId, holderKey, audience, nonce);
          vpTokenMap.put(credentialId, vpTokenString);

        } catch (Exception e) {
          // 개별 실패는 로그만 남기고 계속 진행
        }
      }

      if (vpTokenMap.isEmpty()) {
        throw new RuntimeException("No VP tokens were successfully generated");
      }

      return combineMultipleVPTokens(vpTokenMap);

    } catch (Exception e) {
      throw new RuntimeException("Multiple VP token generation failed", e);
    }
  }

  /**
   * Credential Set 처리
   * OpenID4VP 1.0의 credential_sets 기능 지원
   *
   * @param credentials 사용 가능한 credential 맵
   * @param dcqlQuery DCQL 쿼리 (credential_sets 포함)
   * @param holderKey Holder 개인키
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return VP Token JSON
   */
  public static String generateFromCredentialSets(Map<String, String> credentials,
      DCQLQuery dcqlQuery,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {

      if (dcqlQuery.getCredentialSets() == null || dcqlQuery.getCredentialSets().isEmpty()) {
        // credential_sets가 없으면 일반 처리
        return generateMultipleFromDCQL(credentials, dcqlQuery, holderKey, audience, nonce);
      }

      // credential_sets 처리 - 첫 번째로 만족 가능한 옵션 선택
      for (DCQLQuery.CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
        if (credentialSet.getOptions() != null) {
          for (List<String> option : credentialSet.getOptions()) {

            // 옵션의 모든 credential이 사용 가능한지 확인
            boolean allAvailable = option.stream()
                .allMatch(credentials::containsKey);

            if (allAvailable) {

              Map<String, String> selectedCredentials = new HashMap<>();
              for (String credentialId : option) {
                selectedCredentials.put(credentialId, credentials.get(credentialId));
              }

              return generateMultipleFromDCQL(selectedCredentials, dcqlQuery,
                  holderKey, audience, nonce);
            }
          }
        }
      }

      throw new RuntimeException("No credential set options can be satisfied");

    } catch (Exception e) {
      throw new RuntimeException("Credential sets VP token generation failed", e);
    }
  }

  /**
   * Format별 자동 처리
   *
   * @param credentialId Credential ID
   * @param credentialData Credential 데이터
   * @param format Credential 형식
   * @param dcqlQuery DCQL 쿼리
   * @param holderKey Holder 개인키 (SD-JWT용)
   * @param holderDid Holder DID (JWT/W3C VC용)
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return VP Token JSON
   */
  public static String generateByFormat(String credentialId,
      Object credentialData,
      String format,
      DCQLQuery dcqlQuery,
      PrivateKey holderKey,
      String holderDid,
      String audience,
      String nonce) {


    switch (format.toLowerCase()) {
      case "dc+sd-jwt":
      case "vc+sd-jwt":
      case "sd-jwt":
        if (!(credentialData instanceof String)) {
          throw new IllegalArgumentException("SD-JWT credential data must be a String");
        }
        return generateFromDCQL((String) credentialData, dcqlQuery, credentialId,
            holderKey, audience, nonce);

      case "jwt_vc_json":
      case "jwt_vc":
        // JWT VC는 현재 DCQL 직접 처리 미지원 - fallback to service layer
        throw new UnsupportedOperationException("JWT VC format requires service layer processing");

      case "ldp_vc":
      case "vc+ldp":
        // W3C VC도 현재 DCQL 직접 처리 미지원 - fallback to service layer
        throw new UnsupportedOperationException("W3C VC format requires service layer processing");

      default:
        throw new UnsupportedOperationException("Unsupported credential format: " + format);
    }
  }

  /**
   * 단일 credential을 위한 VP Token 구조 래핑
   *
   * @param credentialId Credential ID
   * @param vpTokenString VP Token 문자열
   * @return OpenID4VP 1.0 규격 VP Token JSON
   */
  public static String wrapSingleCredentialVPToken(String credentialId, String vpTokenString) throws Exception {
    ObjectNode vpToken = objectMapper.createObjectNode();
    ArrayNode presentations = objectMapper.createArrayNode();
    presentations.add(vpTokenString);
    vpToken.set(credentialId, presentations);

    return objectMapper.writeValueAsString(vpToken);
  }

  /**
   * 여러 VP Token을 하나로 결합
   *
   * @param vpTokenMap Credential ID별 VP Token 문자열 맵
   * @return 통합된 VP Token JSON
   */
  public static String combineMultipleVPTokens(Map<String, String> vpTokenMap) throws Exception {
    ObjectNode combinedVpToken = objectMapper.createObjectNode();

    for (Map.Entry<String, String> entry : vpTokenMap.entrySet()) {
      String credentialId = entry.getKey();
      String vpTokenString = entry.getValue();

      ArrayNode presentations = objectMapper.createArrayNode();
      presentations.add(vpTokenString);
      combinedVpToken.set(credentialId, presentations);
    }

    return objectMapper.writeValueAsString(combinedVpToken);
  }

  /**
   * Multiple presentations을 지원하는 VP Token 생성
   * 동일한 credential에서 여러 다른 클레임 조합의 presentation 생성
   *
   * @param credentialId Credential ID
   * @param sdJwtVC SD-JWT VC 문자열
   * @param claimSets 다양한 클레임 조합 목록
   * @param holderKey Holder 개인키
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return Multiple presentations VP Token
   */
  public static String generateMultiplePresentations(String credentialId,
      String sdJwtVC,
      List<Set<String>> claimSets,
      PrivateKey holderKey,
      String audience,
      String nonce) throws Exception {
    try {

      List<String> vpTokenStrings = OID4VPHandler.createMultipleVPTokens(
          sdJwtVC, claimSets, holderKey, audience, nonce);

      ObjectNode vpToken = objectMapper.createObjectNode();
      ArrayNode presentations = objectMapper.createArrayNode();

      for (String vpTokenString : vpTokenStrings) {
        presentations.add(vpTokenString);
      }

      vpToken.set(credentialId, presentations);

      return objectMapper.writeValueAsString(vpToken);

    } catch (SDJWTException e) {
      throw new RuntimeException("Multiple presentations generation failed: " + e.getMessage(), e);
    }
  }

  /**
   * DCQL 통계 정보와 함께 VP Token 생성
   * 디버깅 및 모니터링용
   *
   * @param credentialData SD-JWT VC 문자열
   * @param dcqlQuery DCQL 쿼리
   * @param credentialId Credential ID
   * @param holderKey Holder 개인키
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return 통계 정보가 포함된 결과
   */
  public static DCQLVPTokenResult generateWithStats(String credentialData,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {
      long startTime = System.currentTimeMillis();

      // 클레임 분석
      Set<String> requestedClaims = DCQLClaimsExtractor.extractClaimsForCredential(dcqlQuery, credentialId);

      // VP Token 생성
      String vpToken = generateFromDCQL(credentialData, dcqlQuery, credentialId,
          holderKey, audience, nonce);

      long processingTime = System.currentTimeMillis() - startTime;

      return DCQLVPTokenResult.builder()
          .vpToken(vpToken)
          .success(true)
          .credentialId(credentialId)
          .requestedClaimsCount(requestedClaims.size())
          .processingTimeMs(processingTime)
          .requestedClaims(requestedClaims)
          .build();

    } catch (Exception e) {
      return DCQLVPTokenResult.builder()
          .success(false)
          .error(e.getMessage())
          .credentialId(credentialId)
          .build();
    }
  }

  /**
   * DCQL VP Token 생성 결과
   */
  public static class DCQLVPTokenResult {
    private String vpToken;
    private boolean success;
    private String error;
    private String credentialId;
    private int requestedClaimsCount;
    private long processingTimeMs;
    private Set<String> requestedClaims;

    public static DCQLVPTokenResultBuilder builder() {
      return new DCQLVPTokenResultBuilder();
    }

    // Getters and Setters
    public String getVpToken() { return vpToken; }
    public boolean isSuccess() { return success; }
    public String getError() { return error; }
    public String getCredentialId() { return credentialId; }
    public int getRequestedClaimsCount() { return requestedClaimsCount; }
    public long getProcessingTimeMs() { return processingTimeMs; }
    public Set<String> getRequestedClaims() { return requestedClaims; }

    public static class DCQLVPTokenResultBuilder {
      private String vpToken;
      private boolean success;
      private String error;
      private String credentialId;
      private int requestedClaimsCount;
      private long processingTimeMs;
      private Set<String> requestedClaims;

      public DCQLVPTokenResultBuilder vpToken(String vpToken) { this.vpToken = vpToken; return this; }
      public DCQLVPTokenResultBuilder success(boolean success) { this.success = success; return this; }
      public DCQLVPTokenResultBuilder error(String error) { this.error = error; return this; }
      public DCQLVPTokenResultBuilder credentialId(String credentialId) { this.credentialId = credentialId; return this; }
      public DCQLVPTokenResultBuilder requestedClaimsCount(int count) { this.requestedClaimsCount = count; return this; }
      public DCQLVPTokenResultBuilder processingTimeMs(long time) { this.processingTimeMs = time; return this; }
      public DCQLVPTokenResultBuilder requestedClaims(Set<String> claims) { this.requestedClaims = claims; return this; }

      public DCQLVPTokenResult build() {
        DCQLVPTokenResult result = new DCQLVPTokenResult();
        result.vpToken = this.vpToken;
        result.success = this.success;
        result.error = this.error;
        result.credentialId = this.credentialId;
        result.requestedClaimsCount = this.requestedClaimsCount;
        result.processingTimeMs = this.processingTimeMs;
        result.requestedClaims = this.requestedClaims;
        return result;
      }
    }
  }
}