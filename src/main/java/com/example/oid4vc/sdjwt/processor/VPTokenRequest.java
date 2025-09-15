package com.example.oid4vc.sdjwt.processor;

import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import lombok.Builder;
import lombok.Data;

import java.security.PrivateKey;
import java.util.Set;

/**
 * VP Token 생성 요청 정보를 담는 DTO
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
@Data
@Builder
public class VPTokenRequest {

  /** Credential 식별자 */
  private String credentialId;

  /** Credential 데이터 (SD-JWT 문자열, JsonNode, JWT 등) */
  private Object credentialData;

  /** Credential 형식 ("dc+sd-jwt", "jwt_vc_json", "ldp_vc" 등) */
  private String format;

  /** 요청된 클레임 집합 (null이면 DCQL에서 추출) */
  private Set<String> requestedClaims;

  /** DCQL 쿼리 (클레임 추출용) */
  private DCQLQuery dcqlQuery;

  /** Holder의 개인키 (SD-JWT Key Binding용) */
  private PrivateKey holderPrivateKey;

  /** Holder의 DID (W3C VC, JWT VC용) */
  private String holderDid;

  /** Verifier의 Client ID (audience) */
  private String verifierClientId;

  /** Authorization Request의 nonce */
  private String nonce;

  /** 전체 공개 여부 */
  @Builder.Default
  private boolean fullDisclosure = false;

  /** 최소 공개 여부 */
  @Builder.Default
  private boolean minimalDisclosure = false;

  /** 다중 프레젠테이션 허용 여부 */
  @Builder.Default
  private boolean allowMultiple = false;

  /** 추가 메타데이터 */
  private java.util.Map<String, Object> metadata;

  /**
   * SD-JWT 형식인지 확인
   */
  public boolean isSDJWTFormat() {
    return format != null && (
        format.equals("dc+sd-jwt") ||
            format.equals("vc+sd-jwt") ||
            format.equals("sd-jwt")
    );
  }

  /**
   * JWT VC 형식인지 확인
   */
  public boolean isJWTVCFormat() {
    return format != null && (
        format.equals("jwt_vc_json") ||
            format.equals("jwt_vc")
    );
  }

  /**
   * W3C VC 형식인지 확인
   */
  public boolean isW3CVCFormat() {
    return format != null && format.equals("ldp_vc");
  }

  /**
   * 필수 파라미터 유효성 검증
   */
  public void validate() {
    if (credentialId == null || credentialId.trim().isEmpty()) {
      throw new IllegalArgumentException("Credential ID is required");
    }

    if (credentialData == null) {
      throw new IllegalArgumentException("Credential data is required");
    }

    if (format == null || format.trim().isEmpty()) {
      throw new IllegalArgumentException("Credential format is required");
    }

    if (verifierClientId == null || verifierClientId.trim().isEmpty()) {
      throw new IllegalArgumentException("Verifier client ID is required");
    }

    if (nonce == null || nonce.trim().isEmpty()) {
      throw new IllegalArgumentException("Nonce is required");
    }

    // 형식별 추가 검증
    if (isSDJWTFormat() && holderPrivateKey == null) {
      throw new IllegalArgumentException("Holder private key is required for SD-JWT format");
    }

    if ((isJWTVCFormat() || isW3CVCFormat()) && holderDid == null) {
      throw new IllegalArgumentException("Holder DID is required for JWT VC and W3C VC formats");
    }
  }

  /**
   * 요청된 클레임 획득 (DCQL에서 추출 또는 직접 지정)
   */
  public Set<String> getEffectiveRequestedClaims() {
    if (requestedClaims != null && !requestedClaims.isEmpty()) {
      return requestedClaims;
    }

    if (dcqlQuery != null && credentialId != null) {
      return com.example.oid4vc.sdjwt.dcql.DCQLClaimsExtractor
          .extractClaimsForCredential(dcqlQuery, credentialId);
    }

    return java.util.Collections.emptySet();
  }
}