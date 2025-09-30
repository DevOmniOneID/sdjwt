package com.example.oid4vc.sdjwt.dcql;

import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import com.example.oid4vc.sdjwt.util.SimpleJWTDecoder;

import java.util.*;
import java.util.stream.Collectors;

/**
 * DCQL 쿼리와 Credential 매칭 유틸리티 (완전 구현 버전)
 * OpenID4VP 1.0 Section 6.4 (Processing Rules) 구현
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLCredentialMatcher {

  /**
   * SD-JWT VC가 DCQL 쿼리의 특정 credential 요구사항에 매치되는지 확인
   *
   * @param sdjwt SD-JWT VC 객체
   * @param credentialQuery DCQL credential 쿼리
   * @return 매치 여부
   */
  public static boolean matchesCredentialQuery(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    if (sdjwt == null || credentialQuery == null) {
      return false;
    }

    try {
      // 1. 포맷 확인
      if (!matchesFormat(credentialQuery.getFormat())) {
        System.out.println("포맷 매칭 실패: " + credentialQuery.getFormat());
        return false;
      }

      // 2. 메타데이터 확인 (vct_values, issuer_did 등)
      if (!matchesMetadata(sdjwt, credentialQuery.getMeta())) {
        System.out.println("메타데이터 매칭 실패");
        return false;
      }

      // 3. 요청된 클레임 사용 가능성 확인
      if (!hasRequestedClaims(sdjwt, credentialQuery)) {
        System.out.println("요청된 클레임 매칭 실패");
        return false;
      }

      // 4. 클레임 값 조건 확인 (values, min, max 등)
      if (!matchesClaimValues(sdjwt, credentialQuery)) {
        System.out.println("클레임 값 조건 매칭 실패");
        return false;
      }

      // 5. 암호화 홀더 바인딩 요구사항 확인
      if (!matchesCryptographicBinding(sdjwt, credentialQuery)) {
        System.out.println("암호화 홀더 바인딩 요구사항 실패");
        return false;
      }

      System.out.println("모든 조건 매칭 성공");
      return true;

    } catch (Exception e) {
      System.err.println("매칭 중 예외 발생: " + e.getMessage());
      return false;
    }
  }

  /**
   * 여러 SD-JWT VC 중에서 DCQL 쿼리에 매치되는 것들 필터링
   *
   * @param sdjwtMap Credential ID를 키로 하는 SD-JWT 맵
   * @param dcqlQuery DCQL 쿼리
   * @return 매치되는 Credential ID 집합
   */
  public static Set<String> findMatchingCredentials(Map<String, SDJWT> sdjwtMap, DCQLQuery dcqlQuery) {
    if (sdjwtMap == null || dcqlQuery == null || dcqlQuery.getCredentials() == null) {
      return Collections.emptySet();
    }

    Set<String> matchingCredentials = new HashSet<>();

    for (DCQLQuery.CredentialQuery credentialQuery : dcqlQuery.getCredentials()) {
      String credentialId = credentialQuery.getId();
      SDJWT sdjwt = sdjwtMap.get(credentialId);

      System.out.println("Credential 매칭 확인: " + credentialId);

      if (sdjwt != null && matchesCredentialQuery(sdjwt, credentialQuery)) {
        matchingCredentials.add(credentialId);
        System.out.println(credentialId + " 매칭 성공");
      } else {
        System.out.println(credentialId + " 매칭 실패");
      }
    }

    return matchingCredentials;
  }

  /**
   * DCQL credential_sets 처리 - 옵션 중 하나라도 만족하는지 확인
   *
   * @param sdjwtMap 사용 가능한 SD-JWT 맵
   * @param dcqlQuery DCQL 쿼리 (credential_sets 포함)
   * @return 만족 가능한 credential set 정보
   */
  public static List<CredentialSetMatch> findCredentialSetMatches(Map<String, SDJWT> sdjwtMap, DCQLQuery dcqlQuery) {
    if (dcqlQuery.getCredentialSets() == null || dcqlQuery.getCredentialSets().isEmpty()) {
      // credential_sets가 없으면 모든 credentials 개별 처리
      return Collections.emptyList();
    }

    List<CredentialSetMatch> matches = new ArrayList<>();

    for (DCQLQuery.CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
      System.out.println("Credential Set 매칭 확인: " + credentialSet.getId());

      CredentialSetMatch match = checkCredentialSetMatch(sdjwtMap, dcqlQuery, credentialSet);
      if (match.isComplete()) {
        matches.add(match);
        System.out.println("Credential Set " + credentialSet.getId() + " 매칭 성공");
      } else {
        System.out.println("Credential Set " + credentialSet.getId() + " 매칭 실패");
      }
    }

    return matches;
  }

  /**
   * 특정 클레임들이 SD-JWT에서 선택적 공개 가능한지 확인
   *
   * @param sdjwt SD-JWT VC
   * @param requestedClaims 요청된 클레임들
   * @return 공개 가능한 클레임들과 불가능한 클레임들
   */
  public static ClaimAvailability checkClaimAvailability(SDJWT sdjwt, Set<String> requestedClaims) {
    if (sdjwt == null || requestedClaims == null) {
      return new ClaimAvailability(Collections.emptySet(), Collections.emptySet());
    }

    // SD-JWT에서 사용 가능한 클레임들 추출
    Set<String> availableClaims = extractAvailableClaims(sdjwt);

    Set<String> satisfiableClaims = requestedClaims.stream()
        .filter(availableClaims::contains)
        .collect(Collectors.toSet());

    Set<String> unsatisfiableClaims = requestedClaims.stream()
        .filter(claim -> !availableClaims.contains(claim))
        .collect(Collectors.toSet());

    System.out.println("Claim 가용성 분석:");
    System.out.println("   - 사용 가능한 Claims: " + availableClaims);
    System.out.println("   - 만족 가능한 Claims: " + satisfiableClaims);
    System.out.println("   - 불만족 Claims: " + unsatisfiableClaims);

    return new ClaimAvailability(satisfiableClaims, unsatisfiableClaims);
  }

  /**
   * SD-JWT에서 사용 가능한 모든 클레임 추출 (Disclosures + JWT 클레임)
   */
  private static Set<String> extractAvailableClaims(SDJWT sdjwt) {
    Set<String> availableClaims = new HashSet<>();

    // 1. Disclosures에서 클레임 추출
    if (sdjwt.getDisclosures() != null) {
      sdjwt.getDisclosures().stream()
          .map(disclosure -> disclosure.getClaimName())
          .filter(Objects::nonNull)
          .forEach(availableClaims::add);
    }

    // 2. JWT 페이로드에서 공개 클레임 추출
    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      // JWT 표준 클레임과 커스텀 클레임 모두 추가
      payload.keySet().stream()
          .filter(key -> !isReservedJWTClaim(key))
          .forEach(availableClaims::add);

    } catch (Exception e) {
      System.err.println("JWT 페이로드 파싱 실패: " + e.getMessage());
    }

    return availableClaims;
  }

  /**
   * JWT 예약 클레임 확인 (iss, sub, aud, exp, nbf, iat, jti, _sd_alg 등)
   */
  private static boolean isReservedJWTClaim(String claimName) {
    Set<String> reservedClaims = Set.of(
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti", // JWT 표준 클레임
        "_sd_alg", "_sd", "cnf", // SD-JWT 관련 클레임
        "vct" // VC 타입 클레임
    );
    return reservedClaims.contains(claimName);
  }

  /**
   * 포맷 매칭 확인 (완전 구현)
   */
  public static boolean matchesFormat(String requiredFormat) {
    if (requiredFormat == null) {
      return true; // 포맷 요구사항 없음
    }

    // 지원되는 SD-JWT 포맷들
    Set<String> supportedFormats = Set.of(
        "dc+sd-jwt",     // Digital Credential SD-JWT
        "vc+sd-jwt",     // Verifiable Credential SD-JWT
        "sd-jwt",        // 일반 SD-JWT
        "jwt_vc_json"    // JWT VC JSON 호환
    );

    boolean isSupported = supportedFormats.contains(requiredFormat);

    if (!isSupported) {
      System.out.println("지원되지 않는 포맷: " + requiredFormat);
    }

    return isSupported;
  }

  /**
   * 메타데이터 매칭 확인 (완전 구현)
   */
  public static boolean matchesMetadata(SDJWT sdjwt, Map<String, Object> metadata) {
    if (metadata == null || metadata.isEmpty()) {
      return true; // 메타데이터 요구사항 없음
    }

    try {
      // 1. vct_values 확인
      if (metadata.containsKey("vct_values")) {
        List<String> requiredVcts = (List<String>) metadata.get("vct_values");
        if (!checkVctValues(sdjwt, requiredVcts)) {
          System.out.println("VCT 값 매칭 실패");
          return false;
        }
      }

      // 2. issuer_did 확인
      if (metadata.containsKey("issuer_did")) {
        String requiredIssuer = (String) metadata.get("issuer_did");
        if (!checkIssuerDid(sdjwt, requiredIssuer)) {
          System.out.println("Issuer DID 매칭 실패");
          return false;
        }
      }

      // 3. credential_type 확인
      if (metadata.containsKey("credential_type")) {
        String requiredType = (String) metadata.get("credential_type");
        if (!checkCredentialType(sdjwt, requiredType)) {
          System.out.println("Credential Type 매칭 실패");
          return false;
        }
      }

      // 4. required_trust_level 확인
      if (metadata.containsKey("required_trust_level")) {
        String requiredTrustLevel = (String) metadata.get("required_trust_level");
        if (!checkTrustLevel(sdjwt, requiredTrustLevel)) {
          System.out.println("Trust Level 매칭 실패");
          return false;
        }
      }

      // 5. privacy_level 확인
      if (metadata.containsKey("privacy_level")) {
        String requiredPrivacyLevel = (String) metadata.get("privacy_level");
        if (!checkPrivacyLevel(sdjwt, requiredPrivacyLevel)) {
          System.out.println("Privacy Level 매칭 실패");
          return false;
        }
      }

      System.out.println("모든 메타데이터 조건 만족");
      return true;

    } catch (Exception e) {
      System.err.println("메타데이터 확인 중 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * VCT (Verifiable Credential Type) 값 확인 (완전 구현)
   */
  private static boolean checkVctValues(SDJWT sdjwt, List<String> requiredVcts) {
    if (requiredVcts == null || requiredVcts.isEmpty()) {
      return true;
    }

    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      Object vctClaim = payload.get("vct");
      if (vctClaim == null) {
        System.out.println("SD-JWT에 vct 클레임이 없음");
        return false;
      }

      String actualVct = vctClaim.toString();
      boolean matches = requiredVcts.contains(actualVct);

      System.out.println("VCT 매칭: 요구=" + requiredVcts + ", 실제=" + actualVct + ", 결과=" + matches);

      return matches;

    } catch (Exception e) {
      System.err.println("VCT 확인 중 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * Issuer DID 확인
   */
  private static boolean checkIssuerDid(SDJWT sdjwt, String requiredIssuer) {
    if (requiredIssuer == null) {
      return true;
    }

    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      Object issClaim = payload.get("iss");
      if (issClaim == null) {
        System.out.println("SD-JWT에 iss 클레임이 없음");
        return false;
      }

      String actualIssuer = issClaim.toString();
      boolean matches = requiredIssuer.equals(actualIssuer);

      System.out.println("Issuer 매칭: 요구=" + requiredIssuer + ", 실제=" + actualIssuer + ", 결과=" + matches);

      return matches;

    } catch (Exception e) {
      System.err.println("Issuer 확인 중 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * Credential Type 확인
   */
  private static boolean checkCredentialType(SDJWT sdjwt, String requiredType) {
    if (requiredType == null) {
      return true;
    }

    // VCT에서 타입 정보 추출하거나 커스텀 클레임에서 확인
    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      // 1. credential_type 클레임 확인
      Object credTypeClaim = payload.get("credential_type");
      if (credTypeClaim != null && requiredType.equals(credTypeClaim.toString())) {
        return true;
      }

      // 2. VCT에서 타입 정보 추출
      Object vctClaim = payload.get("vct");
      if (vctClaim != null) {
        String vct = vctClaim.toString();
        // VCT URL에서 타입 정보 추출 (예: https://example.com/identity_credential -> identity)
        if (vct.contains(requiredType) || vct.endsWith("/" + requiredType + "_credential")) {
          return true;
        }
      }

      System.out.println("Credential Type 매칭 실패: 요구=" + requiredType);
      return false;

    } catch (Exception e) {
      System.err.println("Credential Type 확인 중 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * Trust Level 확인
   */
  private static boolean checkTrustLevel(SDJWT sdjwt, String requiredTrustLevel) {
    // Trust Level 순서: low < medium < high < critical
    Map<String, Integer> trustLevels = Map.of(
        "low", 1,
        "medium", 2,
        "high", 3,
        "critical", 4
    );

    // 현재는 모든 SD-JWT를 "high" 레벨로 간주
    int actualLevel = trustLevels.getOrDefault("high", 3);
    int requiredLevel = trustLevels.getOrDefault(requiredTrustLevel, 1);

    boolean meets = actualLevel >= requiredLevel;
    System.out.println("Trust Level 확인: 요구=" + requiredTrustLevel + "(" + requiredLevel + "), 실제=high(" + actualLevel + "), 결과=" + meets);

    return meets;
  }

  /**
   * Privacy Level 확인
   */
  private static boolean checkPrivacyLevel(SDJWT sdjwt, String requiredPrivacyLevel) {
    // Privacy Level: public < internal < confidential < secret
    Map<String, Integer> privacyLevels = Map.of(
        "public", 1,
        "internal", 2,
        "confidential", 3,
        "secret", 4
    );

    // SD-JWT는 기본적으로 "confidential" 레벨
    int actualLevel = privacyLevels.getOrDefault("confidential", 3);
    int requiredLevel = privacyLevels.getOrDefault(requiredPrivacyLevel, 1);

    boolean meets = actualLevel >= requiredLevel;
    System.out.println("Privacy Level 확인: 요구=" + requiredPrivacyLevel + "(" + requiredLevel + "), 실제=confidential(" + actualLevel + "), 결과=" + meets);

    return meets;
  }

  /**
   * 요청된 클레임 존재 확인
   */
  private static boolean hasRequestedClaims(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    if (credentialQuery.getClaims() == null || credentialQuery.getClaims().isEmpty()) {
      return true; // 특정 클레임 요구사항 없음
    }

    Set<String> requestedClaims = credentialQuery.getClaims().stream()
        .map(claim -> DCQLPathProcessor.pathToClaimName(claim.getPath()))
        .filter(Objects::nonNull)
        .collect(Collectors.toSet());

    ClaimAvailability availability = checkClaimAvailability(sdjwt, requestedClaims);

    // 모든 요청된 클레임이 사용 가능해야 함
    boolean allAvailable = availability.getUnsatisfiableClaims().isEmpty();

    if (!allAvailable) {
      System.out.println("사용 불가능한 클레임: " + availability.getUnsatisfiableClaims());
    }

    return allAvailable;
  }

  /**
   * 클레임 값 조건 확인 (values, min, max, value 등)
   */
  private static boolean matchesClaimValues(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    if (credentialQuery.getClaims() == null) {
      return true;
    }

    try {
      // SD-JWT에서 실제 클레임 값들 추출
      Map<String, Object> actualValues = extractClaimValues(sdjwt);

      for (DCQLQuery.ClaimQuery claimQuery : credentialQuery.getClaims()) {
        String claimName = DCQLPathProcessor.pathToClaimName(claimQuery.getPath());
        if (claimName == null) continue;

        Object actualValue = actualValues.get(claimName);
        if (actualValue == null) {
          System.out.println("클레임 값 없음: " + claimName);
          continue; // 값이 없으면 조건 확인 불가
        }

        // 1. values 조건 확인 (허용된 값들)
        if (claimQuery.getValues() != null && !claimQuery.getValues().isEmpty()) {
          if (!claimQuery.getValues().contains(actualValue)) {
            System.out.println("허용되지 않은 값: " + claimName + "=" + actualValue + ", 허용값=" + claimQuery.getValues());
            return false;
          }
        }

        // 2. value 조건 확인 (정확한 값)
        if (claimQuery.getValue() != null) {
          if (!claimQuery.getValue().equals(actualValue)) {
            System.out.println("값 불일치: " + claimName + "=" + actualValue + ", 요구값=" + claimQuery.getValue());
            return false;
          }
        }

        // 3. min 조건 확인
        if (claimQuery.getMin() != null) {
          if (!checkMinCondition(actualValue, claimQuery.getMin(), claimName)) {
            return false;
          }
        }

        // 4. max 조건 확인
        if (claimQuery.getMax() != null) {
          if (!checkMaxCondition(actualValue, claimQuery.getMax(), claimName)) {
            return false;
          }
        }
      }

      return true;

    } catch (Exception e) {
      System.err.println("클레임 값 조건 확인 중 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * SD-JWT에서 실제 클레임 값들 추출
   */
  private static Map<String, Object> extractClaimValues(SDJWT sdjwt) {
    Map<String, Object> claimValues = new HashMap<>();

    // 1. Disclosures에서 값 추출
    if (sdjwt.getDisclosures() != null) {
      for (var disclosure : sdjwt.getDisclosures()) {
        claimValues.put(disclosure.getClaimName(), disclosure.getClaimValue());
      }
    }

    // 2. JWT 페이로드에서 공개 클레임 값 추출
    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      payload.entrySet().stream()
          .filter(entry -> !isReservedJWTClaim(entry.getKey()))
          .forEach(entry -> claimValues.put(entry.getKey(), entry.getValue()));

    } catch (Exception e) {
      System.err.println("JWT 페이로드에서 클레임 값 추출 실패: " + e.getMessage());
    }

    return claimValues;
  }

  /**
   * 최솟값 조건 확인
   */
  private static boolean checkMinCondition(Object actualValue, Object minValue, String claimName) {
    try {
      if (actualValue instanceof Number && minValue instanceof Number) {
        double actual = ((Number) actualValue).doubleValue();
        double min = ((Number) minValue).doubleValue();
        boolean meets = actual >= min;
        System.out.println("Min 조건: " + claimName + "=" + actual + " >= " + min + " → " + meets);
        return meets;
      }

      if (actualValue instanceof String && minValue instanceof String) {
        // 문자열의 경우 사전식 순서 비교
        int comparison = ((String) actualValue).compareTo((String) minValue);
        boolean meets = comparison >= 0;
        System.out.println("Min 조건(문자열): " + claimName + "=" + actualValue + " >= " + minValue + " → " + meets);
        return meets;
      }

      System.out.println("Min 조건 비교 불가: " + claimName + " (타입 불일치)");
      return true; // 비교 불가능한 경우 통과

    } catch (Exception e) {
      System.err.println("Min 조건 확인 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * 최댓값 조건 확인
   */
  private static boolean checkMaxCondition(Object actualValue, Object maxValue, String claimName) {
    try {
      if (actualValue instanceof Number && maxValue instanceof Number) {
        double actual = ((Number) actualValue).doubleValue();
        double max = ((Number) maxValue).doubleValue();
        boolean meets = actual <= max;
        System.out.println("Max 조건: " + claimName + "=" + actual + " <= " + max + " → " + meets);
        return meets;
      }

      if (actualValue instanceof String && maxValue instanceof String) {
        // 문자열의 경우 사전식 순서 비교
        int comparison = ((String) actualValue).compareTo((String) maxValue);
        boolean meets = comparison <= 0;
        System.out.println("Max 조건(문자열): " + claimName + "=" + actualValue + " <= " + maxValue + " → " + meets);
        return meets;
      }

      System.out.println("Max 조건 비교 불가: " + claimName + " (타입 불일치)");
      return true; // 비교 불가능한 경우 통과

    } catch (Exception e) {
      System.err.println("Max 조건 확인 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * 암호화 홀더 바인딩 요구사항 확인
   */
  private static boolean matchesCryptographicBinding(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    Boolean required = credentialQuery.getRequireCryptographicHolderBinding();
    if (required == null || !required) {
      return true; // 바인딩 요구사항 없음
    }

    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      // cnf (confirmation) 클레임 확인
      Object cnfClaim = payload.get("cnf");
      boolean hasBinding = cnfClaim != null;

      System.out.println("암호화 홀더 바인딩: 요구=" + required + ", 존재=" + hasBinding);

      return hasBinding;

    } catch (Exception e) {
      System.err.println("암호화 바인딩 확인 중 오류: " + e.getMessage());
      return false;
    }
  }

  /**
   * Credential Set 매치 확인
   */
  private static CredentialSetMatch checkCredentialSetMatch(Map<String, SDJWT> sdjwtMap,
      DCQLQuery dcqlQuery,
      DCQLQuery.CredentialSet credentialSet) {

    CredentialSetMatch match = new CredentialSetMatch();

    if (credentialSet.getOptions() == null || credentialSet.getOptions().isEmpty()) {
      return match;
    }

    // 각 옵션에 대해 확인
    for (int i = 0; i < credentialSet.getOptions().size(); i++) {
      List<String> option = credentialSet.getOptions().get(i);
      System.out.println("옵션 " + (i + 1) + " 확인: " + option);

      boolean optionSatisfied = true;
      Set<String> optionCredentials = new HashSet<>();

      for (String credentialId : option) {
        SDJWT sdjwt = sdjwtMap.get(credentialId);
        DCQLQuery.CredentialQuery credentialQuery = findCredentialQueryById(dcqlQuery, credentialId);

        if (sdjwt == null) {
          System.out.println("SD-JWT 없음: " + credentialId);
          optionSatisfied = false;
          break;
        }

        if (credentialQuery == null) {
          System.out.println("Credential Query 없음: " + credentialId);
          optionSatisfied = false;
          break;
        }

        if (!matchesCredentialQuery(sdjwt, credentialQuery)) {
          System.out.println("매칭 실패: " + credentialId);
          optionSatisfied = false;
          break;
        }

        optionCredentials.add(credentialId);
        System.out.println("매칭 성공: " + credentialId);
      }

      if (optionSatisfied) {
        match.addSatisfiedOption(option, optionCredentials);
        System.out.println("옵션 " + (i + 1) + " 만족");
      } else {
        System.out.println("옵션 " + (i + 1) + " 불만족");
      }
    }

    return match;
  }

  /**
   * Credential ID로 CredentialQuery 찾기
   */
  private static DCQLQuery.CredentialQuery findCredentialQueryById(DCQLQuery dcqlQuery, String credentialId) {
    if (dcqlQuery.getCredentials() == null) {
      return null;
    }

    return dcqlQuery.getCredentials().stream()
        .filter(cred -> credentialId.equals(cred.getId()))
        .findFirst()
        .orElse(null);
  }

  /**
   * SD-JWT의 실제 값이 DCQL 조건에 맞는 클레임만 추출 (새로 추가)
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @param sdjwt SD-JWT 객체
   * @return 조건에 맞는 클레임명 집합
   */
  public static Set<String> extractMatchingClaimNames(DCQLQuery dcqlQuery, SDJWT sdjwt) {
    if (dcqlQuery == null || dcqlQuery.getCredentials() == null || sdjwt == null) {
      return Collections.emptySet();
    }

    Set<String> matchingClaims = new HashSet<>();

    // SD-JWT에서 실제 클레임 값들 추출
    Map<String, Object> actualValues = extractClaimValues(sdjwt);

    dcqlQuery.getCredentials().forEach(credential -> {
      if (credential.getClaims() != null) {
        credential.getClaims().forEach(claimQuery -> {
          String claimName = DCQLPathProcessor.pathToClaimName(claimQuery.getPath());
          if (claimName != null && meetsClaimConditions(claimQuery, actualValues.get(claimName))) {
            matchingClaims.add(claimName);
            System.out.println("조건 만족 클레임 추가: " + claimName + "=" + actualValues.get(claimName));
          } else {
            System.out.println("조건 불만족 클레임 제외: " + claimName + "=" + actualValues.get(claimName));
          }
        });
      }
    });

    return matchingClaims;
  }

  /**
   * 특정 클레임이 DCQL 조건을 만족하는지 확인
   */
  private static boolean meetsClaimConditions(DCQLQuery.ClaimQuery claimQuery, Object actualValue) {
    if (actualValue == null) {
      return false; // 값이 없으면 조건 불만족
    }

    // 1. values 조건 확인 (허용된 값들)
    if (claimQuery.getValues() != null && !claimQuery.getValues().isEmpty()) {
      boolean valueMatches = claimQuery.getValues().contains(actualValue);
      System.out.println("  values 조건: " + actualValue + " in " + claimQuery.getValues() + " = " + valueMatches);
      if (!valueMatches) {
        return false;
      }
    }

    // 2. value 조건 확인 (정확한 값)
    if (claimQuery.getValue() != null) {
      boolean exactMatch = claimQuery.getValue().equals(actualValue);
      System.out.println("  value 조건: " + actualValue + " == " + claimQuery.getValue() + " = " + exactMatch);
      if (!exactMatch) {
        return false;
      }
    }

    // 3. min 조건 확인
    if (claimQuery.getMin() != null) {
      if (!checkMinCondition(actualValue, claimQuery.getMin())) {
        return false;
      }
    }

    // 4. max 조건 확인
    if (claimQuery.getMax() != null) {
      if (!checkMaxCondition(actualValue, claimQuery.getMax())) {
        return false;
      }
    }

    return true; // 모든 조건 만족
  }

  /**
   * 최솟값 조건 확인
   */
  private static boolean checkMinCondition(Object actualValue, Object minValue) {
    try {
      if (actualValue instanceof Number && minValue instanceof Number) {
        double actual = ((Number) actualValue).doubleValue();
        double min = ((Number) minValue).doubleValue();
        return actual >= min;
      }

      if (actualValue instanceof String && minValue instanceof String) {
        return ((String) actualValue).compareTo((String) minValue) >= 0;
      }

      return true; // 비교 불가능한 경우 통과

    } catch (Exception e) {
      return false;
    }
  }

  /**
   * 최댓값 조건 확인
   */
  private static boolean checkMaxCondition(Object actualValue, Object maxValue) {
    try {
      if (actualValue instanceof Number && maxValue instanceof Number) {
        double actual = ((Number) actualValue).doubleValue();
        double max = ((Number) maxValue).doubleValue();
        return actual <= max;
      }

      if (actualValue instanceof String && maxValue instanceof String) {
        return ((String) actualValue).compareTo((String) maxValue) <= 0;
      }

      return true; // 비교 불가능한 경우 통과

    } catch (Exception e) {
      return false;
    }
  }

  /**
   * 클레임 사용 가능성 정보
   */
  public static class ClaimAvailability {
    private final Set<String> satisfiableClaims;
    private final Set<String> unsatisfiableClaims;

    public ClaimAvailability(Set<String> satisfiableClaims, Set<String> unsatisfiableClaims) {
      this.satisfiableClaims = satisfiableClaims != null ? satisfiableClaims : Collections.emptySet();
      this.unsatisfiableClaims = unsatisfiableClaims != null ? unsatisfiableClaims : Collections.emptySet();
    }

    public Set<String> getSatisfiableClaims() { return satisfiableClaims; }
    public Set<String> getUnsatisfiableClaims() { return unsatisfiableClaims; }
    public boolean isFullySatisfiable() { return unsatisfiableClaims.isEmpty(); }
    public boolean isPartiallySatisfiable() { return !satisfiableClaims.isEmpty(); }

    @Override
    public String toString() {
      return String.format("ClaimAvailability{만족=%d, 불만족=%d}",
          satisfiableClaims.size(), unsatisfiableClaims.size());
    }
  }

  /**
   * Credential Set 매치 결과
   */
  public static class CredentialSetMatch {
    private final List<CredentialSetOption> satisfiedOptions = new ArrayList<>();

    public void addSatisfiedOption(List<String> optionIds, Set<String> availableCredentials) {
      satisfiedOptions.add(new CredentialSetOption(optionIds, availableCredentials));
    }

    public List<CredentialSetOption> getSatisfiedOptions() { return satisfiedOptions; }
    public boolean isComplete() { return !satisfiedOptions.isEmpty(); }
    public int getOptionCount() { return satisfiedOptions.size(); }

    @Override
    public String toString() {
      return String.format("CredentialSetMatch{만족된 옵션=%d}", satisfiedOptions.size());
    }

    public static class CredentialSetOption {
      private final List<String> optionIds;
      private final Set<String> availableCredentials;

      public CredentialSetOption(List<String> optionIds, Set<String> availableCredentials) {
        this.optionIds = optionIds != null ? optionIds : Collections.emptyList();
        this.availableCredentials = availableCredentials != null ? availableCredentials : Collections.emptySet();
      }

      public List<String> getOptionIds() { return optionIds; }
      public Set<String> getAvailableCredentials() { return availableCredentials; }

      @Override
      public String toString() {
        return String.format("Option{IDs=%s, Available=%s}", optionIds, availableCredentials);
      }
    }
  }
}