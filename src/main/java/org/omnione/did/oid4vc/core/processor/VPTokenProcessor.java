package org.omnione.did.oid4vc.core.processor;

import org.omnione.did.oid4vc.sdjwt.core.SDJWT;
import org.omnione.did.oid4vc.core.dcql.DCQLQueryValidator;
import org.omnione.did.oid4vc.core.dto.DCQLQuery;
import org.omnione.did.oid4vc.core.oid4vp.OID4VPHandler;
import org.omnione.did.oid4vc.core.oid4vp.VPTokenGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.omnione.did.oid4vc.sdjwt.exception.SDJWTException;

import java.util.*;
import java.util.stream.Collectors;

/**
 * VP Token 생성/처리 통합 프로세서
 * 모든 Credential 형식에 대한 통합 인터페이스 제공
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class VPTokenProcessor {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * One-stop VP Token 생성
   *
   * @param request VP Token 생성 요청
   * @return VP Token 생성 결과
   */
  public static VPTokenResult createVPToken(VPTokenRequest request) {
    long startTime = System.currentTimeMillis();

    try {
      // 1. 요청 유효성 검증
      request.validate();

      // 2. DCQL 검증 (있는 경우)
      VPTokenResult validationResult = validateDCQLIfPresent(request);
      if (!validationResult.isSuccess()) {
        return validationResult.withProcessingTime(startTime);
      }

      // 3. 형식별 VP Token 생성
      VPTokenResult result = generateByFormat(request);

      // 4. 결과 후처리
      return result
          .withProcessingTime(startTime)
          .withOriginalRequest(request);

    } catch (IllegalArgumentException e) {
      return VPTokenResult.failure("Invalid request: " + e.getMessage())
          .withProcessingTime(startTime)
          .withOriginalRequest(request);
    } catch (Exception e) {
      return VPTokenResult.failure("VP token creation failed", e)
          .withProcessingTime(startTime)
          .withOriginalRequest(request);
    }
  }

  /**
   * 배치 처리 - 여러 VP Token 생성
   *
   * @param requests VP Token 생성 요청 목록
   * @return VP Token 생성 결과 목록
   */
  public static List<VPTokenResult> createMultipleVPTokens(List<VPTokenRequest> requests) {
    if (requests == null || requests.isEmpty()) {
      return Collections.emptyList();
    }


    return requests.parallelStream()
        .map(VPTokenProcessor::createVPToken)
        .collect(Collectors.toList());
  }

  /**
   * 검증 및 생성 통합
   *
   * @param request VP Token 생성 요청
   * @return 검증과 생성이 통합된 결과
   */
  public static VPTokenResult processAndValidate(VPTokenRequest request) {
    VPTokenResult result = createVPToken(request);

    if (result.isSuccess()) {
      // 추가 검증 로직 수행
      result = performAdditionalValidation(result);
    }

    return result;
  }

  /**
   * DCQL 쿼리 전처리 + VP Token 생성
   *
   * @param sdJwtVC SD-JWT VC 문자열
   * @param dcqlQuery DCQL 쿼리
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @param holderPrivateKey Holder 개인키
   * @return VP Token 결과
   */
  public static VPTokenResult processWithDCQL(String sdJwtVC,
      DCQLQuery dcqlQuery,
      String audience,
      String nonce,
      java.security.PrivateKey holderPrivateKey) {

    if (dcqlQuery.getCredentials() == null || dcqlQuery.getCredentials().isEmpty()) {
      return VPTokenResult.failure("DCQL query has no credentials");
    }

    // 첫 번째 credential 처리 (단순화)
    var firstCredential = dcqlQuery.getCredentials().get(0);

    VPTokenRequest request = VPTokenRequest.builder()
        .credentialId(firstCredential.getId())
        .credentialData(sdJwtVC)
        .format(firstCredential.getFormat())
        .dcqlQuery(dcqlQuery)
        .holderPrivateKey(holderPrivateKey)
        .verifierClientId(audience)
        .nonce(nonce)
        .build();

    return createVPToken(request);
  }

  /**
   * Credential 형식별 자동 처리
   */
  private static VPTokenResult generateByFormat(VPTokenRequest request) {
    switch (request.getFormat()) {
      case "dc+sd-jwt":
      case "vc+sd-jwt":
      case "sd-jwt":
        return generateSDJWTVPToken(request);

      case "jwt_vc_json":
      case "jwt_vc":
        return generateJWTVCVPToken(request);

      case "ldp_vc":
        return generateW3CVPToken(request);

      default:
        return VPTokenResult.failure("Unsupported credential format: " + request.getFormat());
    }
  }

  /**
   * SD-JWT VP Token 생성
   */
  private static VPTokenResult generateSDJWTVPToken(VPTokenRequest request) {
    try {
      if (!(request.getCredentialData() instanceof String)) {
        return VPTokenResult.failure("SD-JWT credential data must be a String");
      }

      String sdJwtVC = (String) request.getCredentialData();
      Set<String> requestedClaims = request.getEffectiveRequestedClaims();

      // 선택적 공개 처리
      SDJWT originalSDJWT = SDJWT.parse(sdJwtVC);

      String vpTokenString;
      SelectiveDisclosureProcessor.SelectiveDisclosureStats stats = null;

      if (request.isFullDisclosure()) {
        vpTokenString = OID4VPHandler.createFullVPToken(
            sdJwtVC, request.getHolderPrivateKey(),
            request.getVerifierClientId(), request.getNonce());

        stats = SelectiveDisclosureProcessor.generateStats(
            originalSDJWT.getDisclosures(), originalSDJWT.getDisclosures(), requestedClaims);

      } else if (request.isMinimalDisclosure()) {
        vpTokenString = OID4VPHandler.createMinimalVPToken(
            sdJwtVC, request.getHolderPrivateKey(),
            request.getVerifierClientId(), request.getNonce());

        stats = SelectiveDisclosureProcessor.generateStats(
            originalSDJWT.getDisclosures(), Collections.emptyList(), requestedClaims);

      } else {
        vpTokenString = OID4VPHandler.createVPToken(
            sdJwtVC, requestedClaims, request.getHolderPrivateKey(),
            request.getVerifierClientId(), request.getNonce());

        var filteredDisclosures = SelectiveDisclosureProcessor.filterDisclosures(
            originalSDJWT.getDisclosures(), requestedClaims);

        stats = SelectiveDisclosureProcessor.generateStats(
            originalSDJWT.getDisclosures(), filteredDisclosures, requestedClaims);
      }

      // OpenID4VP 구조로 래핑
      String vpToken = wrapInVPTokenStructure(request.getCredentialId(), vpTokenString);

      VPTokenResult result = VPTokenResult.success(vpToken, stats);

      if (stats != null && !stats.getUnsatisfiableClaims().isEmpty()) {
        result.addWarning("Some requested claims are not available: " +
            stats.getUnsatisfiableClaims());
      }

      return result;

    } catch (SDJWTException e) {
      return VPTokenResult.failure("Key binding JWT creation failed", e);
    } catch (Exception e) {
      return VPTokenResult.failure("SD-JWT VP token generation failed", e);
    }
  }

  /**
   * JWT VC VP Token 생성
   */
  private static VPTokenResult generateJWTVCVPToken(VPTokenRequest request) {
    try {
      if (!(request.getCredentialData() instanceof String)) {
        return VPTokenResult.failure("JWT VC credential data must be a String");
      }

      VPTokenGenerator generator = new VPTokenGenerator();
      String vpToken = generator.generateJWTVCVPToken(
          request.getCredentialId(),
          (String) request.getCredentialData(),
          request.getHolderDid(),
          request.getVerifierClientId(),
          request.getNonce()
      );

      return VPTokenResult.success(vpToken);

    } catch (Exception e) {
      return VPTokenResult.failure("JWT VC VP token generation failed", e);
    }
  }

  /**
   * W3C VC VP Token 생성
   */
  private static VPTokenResult generateW3CVPToken(VPTokenRequest request) {
    try {
      if (!(request.getCredentialData() instanceof JsonNode)) {
        return VPTokenResult.failure("W3C VC credential data must be a JsonNode");
      }

      VPTokenGenerator generator = new VPTokenGenerator();
      String vpToken = generator.generateW3CVPToken(
          request.getCredentialId(),
          (JsonNode) request.getCredentialData(),
          request.getHolderDid(),
          request.getVerifierClientId(),
          request.getNonce()
      );

      return VPTokenResult.success(vpToken);

    } catch (Exception e) {
      return VPTokenResult.failure("W3C VC VP token generation failed", e);
    }
  }

  /**
   * DCQL 검증
   */
  private static VPTokenResult validateDCQLIfPresent(VPTokenRequest request) {
    if (request.getDcqlQuery() == null) {
      return VPTokenResult.success(null); // DCQL 없음, 정상
    }

    DCQLQueryValidator.ValidationResult validation =
        DCQLQueryValidator.validate(request.getDcqlQuery());

    if (!validation.isValid()) {
      String errorMsg = "DCQL validation failed: " + String.join(", ", validation.getErrors());
      return VPTokenResult.failure(errorMsg);
    }

    VPTokenResult result = VPTokenResult.success(null);

    // 경고사항 추가
    for (String warning : validation.getWarnings()) {
      result.addWarning("DCQL: " + warning);
    }

    return result;
  }

  /**
   * VP Token을 OpenID4VP 구조로 래핑
   */
  private static String wrapInVPTokenStructure(String credentialId, String vpTokenString) throws Exception {
    var vpToken = objectMapper.createObjectNode();
    var presentations = objectMapper.createArrayNode();
    presentations.add(vpTokenString);
    vpToken.set(credentialId, presentations);
    return objectMapper.writeValueAsString(vpToken);
  }

  /**
   * 추가 검증 수행
   */
  private static VPTokenResult performAdditionalValidation(VPTokenResult result) {
    // VP Token 구조 검증
    if (!result.hasValidVPToken()) {
      return VPTokenResult.failure("Generated VP token is invalid");
    }

    try {
      // JSON 구조 검증
      JsonNode vpTokenJson = objectMapper.readTree(result.getVpToken());
      if (!vpTokenJson.isObject()) {
        result.addWarning("VP token is not a valid JSON object");
      }

      // 추가 검증 로직...

    } catch (Exception e) {
      result.addWarning("VP token JSON validation failed: " + e.getMessage());
    }

    return result;
  }
}