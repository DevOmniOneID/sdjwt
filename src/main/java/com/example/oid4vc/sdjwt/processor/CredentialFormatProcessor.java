package com.example.oid4vc.sdjwt.processor;

import com.example.oid4vc.sdjwt.core.SDJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Credential 형식별 처리 유틸리티
 * 다양한 Credential 형식에 대한 공통 처리 로직 제공
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
@Slf4j
public class CredentialFormatProcessor {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  // 지원하는 Credential 형식들
  public static final Set<String> SUPPORTED_FORMATS = Set.of(
      "dc+sd-jwt", "vc+sd-jwt", "sd-jwt",      // SD-JWT 계열
      "jwt_vc_json", "jwt_vc",                  // JWT VC 계열
      "ldp_vc", "vc+ldp"                       // W3C VC 계열
  );

  /**
   * Credential 형식 검증
   *
   * @param format 검증할 형식
   * @return 지원 여부
   */
  public static boolean isSupportedFormat(String format) {
    return format != null && SUPPORTED_FORMATS.contains(format.toLowerCase());
  }

  /**
   * Credential 데이터 타입 검증
   *
   * @param credentialData Credential 데이터
   * @param expectedFormat 예상 형식
   * @return 검증 결과
   */
  public static FormatValidationResult validateCredentialData(Object credentialData, String expectedFormat) {
    if (credentialData == null) {
      return FormatValidationResult.invalid("Credential data is null");
    }

    if (expectedFormat == null) {
      return FormatValidationResult.invalid("Expected format is null");
    }

    try {
      switch (expectedFormat.toLowerCase()) {
        case "dc+sd-jwt":
        case "vc+sd-jwt":
        case "sd-jwt":
          return validateSDJWTData(credentialData);

        case "jwt_vc_json":
        case "jwt_vc":
          return validateJWTVCData(credentialData);

        case "ldp_vc":
        case "vc+ldp":
          return validateW3CVCData(credentialData);

        default:
          return FormatValidationResult.invalid("Unsupported format: " + expectedFormat);
      }
    } catch (Exception e) {
      log.error("Error validating credential data for format {}", expectedFormat, e);
      return FormatValidationResult.invalid("Validation error: " + e.getMessage());
    }
  }

  /**
   * Credential에서 사용 가능한 클레임 추출
   *
   * @param credentialData Credential 데이터
   * @param format Credential 형식
   * @return 사용 가능한 클레임 집합
   */
  public static Set<String> extractAvailableClaims(Object credentialData, String format) {
    if (credentialData == null || format == null) {
      return Collections.emptySet();
    }

    try {
      switch (format.toLowerCase()) {
        case "dc+sd-jwt":
        case "vc+sd-jwt":
        case "sd-jwt":
          return extractSDJWTClaims(credentialData);

        case "jwt_vc_json":
        case "jwt_vc":
          return extractJWTVCClaims(credentialData);

        case "ldp_vc":
        case "vc+ldp":
          return extractW3CVCClaims(credentialData);

        default:
          log.warn("Unsupported format for claim extraction: {}", format);
          return Collections.emptySet();
      }
    } catch (Exception e) {
      log.error("Error extracting claims for format {}", format, e);
      return Collections.emptySet();
    }
  }

  /**
   * Credential 메타데이터 추출
   *
   * @param credentialData Credential 데이터
   * @param format Credential 형식
   * @return 메타데이터 맵
   */
  public static Map<String, Object> extractCredentialMetadata(Object credentialData, String format) {
    Map<String, Object> metadata = new HashMap<>();

    if (credentialData == null || format == null) {
      return metadata;
    }

    try {
      metadata.put("format", format);
      metadata.put("dataType", credentialData.getClass().getSimpleName());

      switch (format.toLowerCase()) {
        case "dc+sd-jwt":
        case "vc+sd-jwt":
        case "sd-jwt":
          addSDJWTMetadata(credentialData, metadata);
          break;

        case "jwt_vc_json":
        case "jwt_vc":
          addJWTVCMetadata(credentialData, metadata);
          break;

        case "ldp_vc":
        case "vc+ldp":
          addW3CVCMetadata(credentialData, metadata);
          break;
      }

    } catch (Exception e) {
      log.error("Error extracting metadata for format {}", format, e);
      metadata.put("error", e.getMessage());
    }

    return metadata;
  }

  /**
   * Credential 형식별 처리 전략 반환
   *
   * @param format Credential 형식
   * @return 처리 전략
   */
  public static CredentialProcessingStrategy getProcessingStrategy(String format) {
    if (format == null) {
      return CredentialProcessingStrategy.UNSUPPORTED;
    }

    switch (format.toLowerCase()) {
      case "dc+sd-jwt":
      case "vc+sd-jwt":
      case "sd-jwt":
        return CredentialProcessingStrategy.SD_JWT;

      case "jwt_vc_json":
      case "jwt_vc":
        return CredentialProcessingStrategy.JWT_VC;

      case "ldp_vc":
      case "vc+ldp":
        return CredentialProcessingStrategy.W3C_VC;

      default:
        return CredentialProcessingStrategy.UNSUPPORTED;
    }
  }

  // Private helper methods for format-specific validation

  private static FormatValidationResult validateSDJWTData(Object data) {
    if (!(data instanceof String)) {
      return FormatValidationResult.invalid("SD-JWT data must be a String");
    }

    String sdJwtString = (String) data;
    if (!sdJwtString.contains("~")) {
      return FormatValidationResult.invalid("Invalid SD-JWT format (missing ~ separators)");
    }

    try {
      SDJWT.parse(sdJwtString);
      return FormatValidationResult.valid("Valid SD-JWT format");
    } catch (Exception e) {
      return FormatValidationResult.invalid("SD-JWT parsing failed: " + e.getMessage());
    }
  }

  private static FormatValidationResult validateJWTVCData(Object data) {
    if (!(data instanceof String)) {
      return FormatValidationResult.invalid("JWT VC data must be a String");
    }

    String jwtString = (String) data;
    String[] parts = jwtString.split("\\.");
    if (parts.length != 3) {
      return FormatValidationResult.invalid("Invalid JWT format (must have 3 parts)");
    }

    return FormatValidationResult.valid("Valid JWT VC format");
  }

  private static FormatValidationResult validateW3CVCData(Object data) {
    if (!(data instanceof JsonNode)) {
      return FormatValidationResult.invalid("W3C VC data must be a JsonNode");
    }

    JsonNode vcNode = (JsonNode) data;
    if (!vcNode.isObject()) {
      return FormatValidationResult.invalid("W3C VC must be a JSON object");
    }

    if (!vcNode.has("@context") || !vcNode.has("type")) {
      return FormatValidationResult.invalid("W3C VC must have @context and type fields");
    }

    return FormatValidationResult.valid("Valid W3C VC format");
  }

  private static Set<String> extractSDJWTClaims(Object data) {
    try {
      SDJWT sdjwt = SDJWT.parse((String) data);
      return sdjwt.getDisclosures().stream()
          .map(disclosure -> disclosure.getClaimName())
          .collect(java.util.stream.Collectors.toSet());
    } catch (Exception e) {
      log.error("Error extracting SD-JWT claims", e);
      return Collections.emptySet();
    }
  }

  private static Set<String> extractJWTVCClaims(Object data) {
    // JWT VC의 클레임 추출 로직
    // 실제 구현에서는 JWT를 디코딩하여 클레임 추출 필요
    Set<String> claims = new HashSet<>();
    claims.add("iss");
    claims.add("sub");
    claims.add("vc");
    return claims;
  }

  private static Set<String> extractW3CVCClaims(Object data) {
    try {
      JsonNode vcNode = (JsonNode) data;
      Set<String> claims = new HashSet<>();

      if (vcNode.has("credentialSubject")) {
        JsonNode subject = vcNode.get("credentialSubject");
        subject.fieldNames().forEachRemaining(claims::add);
      }

      return claims;
    } catch (Exception e) {
      log.error("Error extracting W3C VC claims", e);
      return Collections.emptySet();
    }
  }

  private static void addSDJWTMetadata(Object data, Map<String, Object> metadata) {
    try {
      SDJWT sdjwt = SDJWT.parse((String) data);
      metadata.put("disclosureCount", sdjwt.getDisclosures().size());
      metadata.put("hasKeyBinding", sdjwt.getKeyBindingJwt() != null);
    } catch (Exception e) {
      metadata.put("parseError", e.getMessage());
    }
  }

  private static void addJWTVCMetadata(Object data, Map<String, Object> metadata) {
    String jwtString = (String) data;
    String[] parts = jwtString.split("\\.");
    metadata.put("jwtParts", parts.length);
    metadata.put("hasSignature", parts.length == 3 && !parts[2].isEmpty());
  }

  private static void addW3CVCMetadata(Object data, Map<String, Object> metadata) {
    try {
      JsonNode vcNode = (JsonNode) data;
      if (vcNode.has("@context")) {
        metadata.put("contexts", vcNode.get("@context"));
      }
      if (vcNode.has("type")) {
        metadata.put("types", vcNode.get("type"));
      }
      metadata.put("hasProof", vcNode.has("proof"));
    } catch (Exception e) {
      metadata.put("metadataError", e.getMessage());
    }
  }

  /**
   * 형식 검증 결과
   */
  public static class FormatValidationResult {
    private final boolean valid;
    private final String message;

    private FormatValidationResult(boolean valid, String message) {
      this.valid = valid;
      this.message = message;
    }

    public static FormatValidationResult valid(String message) {
      return new FormatValidationResult(true, message);
    }

    public static FormatValidationResult invalid(String message) {
      return new FormatValidationResult(false, message);
    }

    public boolean isValid() { return valid; }
    public String getMessage() { return message; }
  }

  /**
   * Credential 처리 전략
   */
  public enum CredentialProcessingStrategy {
    SD_JWT("Selective Disclosure JWT"),
    JWT_VC("JWT Verifiable Credential"),
    W3C_VC("W3C Verifiable Credential"),
    UNSUPPORTED("Unsupported Format");

    private final String description;

    CredentialProcessingStrategy(String description) {
      this.description = description;
    }

    public String getDescription() { return description; }

    public boolean requiresPrivateKey() {
      return this == SD_JWT;
    }

    public boolean requiresHolderDid() {
      return this == JWT_VC || this == W3C_VC;
    }
  }
}