package com.example.oid4vc.sdjwt.dcql;

import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

/**
 * DCQL 쿼리와 Credential 매칭 유틸리티
 * OpenID4VP 1.0 Section 6.4 (Processing Rules) 구현
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
@Slf4j
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
      log.warn("SDJWT or credential query is null");
      return false;
    }

    try {
      // 1. 포맷 확인
      if (!matchesFormat(credentialQuery.getFormat())) {
        log.debug("Format mismatch for credential: {}", credentialQuery.getId());
        return false;
      }

      // 2. 메타데이터 확인 (vct_values 등)
      if (!matchesMetadata(sdjwt, credentialQuery.getMeta())) {
        log.debug("Metadata mismatch for credential: {}", credentialQuery.getId());
        return false;
      }

      // 3. 요청된 클레임 사용 가능성 확인
      if (!hasRequestedClaims(sdjwt, credentialQuery)) {
        log.debug("Required claims not available for credential: {}", credentialQuery.getId());
        return false;
      }

      log.debug("Credential {} matches query requirements", credentialQuery.getId());
      return true;

    } catch (Exception e) {
      log.error("Error matching credential query for {}", credentialQuery.getId(), e);
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

      if (sdjwt != null && matchesCredentialQuery(sdjwt, credentialQuery)) {
        matchingCredentials.add(credentialId);
      }
    }

    log.info("Found {} matching credentials out of {} available",
        matchingCredentials.size(), sdjwtMap.size());
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
      CredentialSetMatch match = checkCredentialSetMatch(sdjwtMap, dcqlQuery, credentialSet);
      if (match.isComplete()) {
        matches.add(match);
      }
    }

    log.debug("Found {} satisfiable credential sets", matches.size());
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

    Set<String> availableClaims = sdjwt.getDisclosures().stream()
        .map(disclosure -> disclosure.getClaimName())
        .collect(Collectors.toSet());

    Set<String> satisfiableClaims = requestedClaims.stream()
        .filter(availableClaims::contains)
        .collect(Collectors.toSet());

    Set<String> unsatisfiableClaims = requestedClaims.stream()
        .filter(claim -> !availableClaims.contains(claim))
        .collect(Collectors.toSet());

    return new ClaimAvailability(satisfiableClaims, unsatisfiableClaims);
  }

  private static boolean matchesFormat(String requiredFormat) {
    // SD-JWT 포맷들 지원
    return "dc+sd-jwt".equals(requiredFormat) ||
        "vc+sd-jwt".equals(requiredFormat) ||
        "sd-jwt".equals(requiredFormat);
  }

  private static boolean matchesMetadata(SDJWT sdjwt, Map<String, Object> metadata) {
    if (metadata == null || metadata.isEmpty()) {
      return true; // 메타데이터 요구사항 없음
    }

    try {
      // vct_values 확인 (SD-JWT VC의 vct 클레임과 매치)
      if (metadata.containsKey("vct_values")) {
        List<String> requiredVcts = (List<String>) metadata.get("vct_values");
        return checkVctValues(sdjwt, requiredVcts);
      }

      // 기타 메타데이터 확인 로직 추가 가능

      return true;

    } catch (Exception e) {
      log.error("Error checking metadata", e);
      return false;
    }
  }

  private static boolean checkVctValues(SDJWT sdjwt, List<String> requiredVcts) {
    if (requiredVcts == null || requiredVcts.isEmpty()) {
      return true;
    }

    // TODO: SD-JWT의 vct 클레임 값과 비교하는 로직 구현
    // 현재는 임시로 true 반환
    log.debug("VCT values check not fully implemented - returning true");
    return true;
  }

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
    return availability.getUnsatisfiableClaims().isEmpty();
  }

  private static CredentialSetMatch checkCredentialSetMatch(Map<String, SDJWT> sdjwtMap,
      DCQLQuery dcqlQuery,
      DCQLQuery.CredentialSet credentialSet) {

    CredentialSetMatch match = new CredentialSetMatch();

    if (credentialSet.getOptions() == null || credentialSet.getOptions().isEmpty()) {
      return match;
    }

    // 각 옵션에 대해 확인
    for (List<String> option : credentialSet.getOptions()) {
      boolean optionSatisfied = true;
      Set<String> optionCredentials = new HashSet<>();

      for (String credentialId : option) {
        SDJWT sdjwt = sdjwtMap.get(credentialId);
        DCQLQuery.CredentialQuery credentialQuery = findCredentialQueryById(dcqlQuery, credentialId);

        if (sdjwt == null || credentialQuery == null ||
            !matchesCredentialQuery(sdjwt, credentialQuery)) {
          optionSatisfied = false;
          break;
        }
        optionCredentials.add(credentialId);
      }

      if (optionSatisfied) {
        match.addSatisfiedOption(option, optionCredentials);
      }
    }

    return match;
  }

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

    public static class CredentialSetOption {
      private final List<String> optionIds;
      private final Set<String> availableCredentials;

      public CredentialSetOption(List<String> optionIds, Set<String> availableCredentials) {
        this.optionIds = optionIds != null ? optionIds : Collections.emptyList();
        this.availableCredentials = availableCredentials != null ? availableCredentials : Collections.emptySet();
      }

      public List<String> getOptionIds() { return optionIds; }
      public Set<String> getAvailableCredentials() { return availableCredentials; }
    }
  }
}