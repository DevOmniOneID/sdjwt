package com.example.oid4vc.sdjwt.processor;

import com.example.oid4vc.sdjwt.core.Disclosure;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.dcql.DCQLClaimsExtractor;
import com.example.oid4vc.sdjwt.dcql.DCQLPathProcessor;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 선택적 공개 처리 전용 프로세서
 * OpenID4VP 1.0 Section 6.4 (Processing Rules) 구현
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SelectiveDisclosureProcessor {

  /**
   * DCQL 기반 선택적 공개 처리
   *
   * @param originalSDJWT 원본 SD-JWT 문자열
   * @param dcqlQuery DCQL 쿼리
   * @param credentialId 처리할 credential ID
   * @return 선택적 공개가 적용된 SD-JWT 객체
   */
  public static SDJWT processSelectiveDisclosure(String originalSDJWT, DCQLQuery dcqlQuery, String credentialId) {
    if (originalSDJWT == null || dcqlQuery == null || credentialId == null) {
      return null;
    }

    try {
      // 1. 원본 SD-JWT 파싱
      SDJWT sdjwt = SDJWT.parse(originalSDJWT);

      // 2. DCQL에서 요청된 클레임 추출
      Set<String> requestedClaims = DCQLClaimsExtractor.extractClaimsForCredential(dcqlQuery, credentialId);

      if (requestedClaims.isEmpty()) {
        return new SDJWT(sdjwt.getCredentialJwt(), Collections.emptyList());
      }

      // 3. 선택적 공개 필터링
      List<Disclosure> filteredDisclosures = filterDisclosures(sdjwt.getDisclosures(), requestedClaims);


      return new SDJWT(sdjwt.getCredentialJwt(), filteredDisclosures);

    } catch (Exception e) {
      throw new RuntimeException("Selective disclosure processing failed", e);
    }
  }

  /**
   * 클레임 필터링
   *
   * @param disclosures 모든 disclosure 목록
   * @param requestedClaims 요청된 클레임 집합
   * @return 필터링된 disclosure 목록
   */
  public static List<Disclosure> filterDisclosures(List<Disclosure> disclosures, Set<String> requestedClaims) {
    if (disclosures == null || disclosures.isEmpty()) {
      return Collections.emptyList();
    }

    if (requestedClaims == null || requestedClaims.isEmpty()) {
      return Collections.emptyList();
    }

    List<Disclosure> filteredDisclosures = disclosures.stream()
        .filter(disclosure -> {
          String claimName = disclosure.getClaimName();
          boolean isRequested = isClaimRequested(claimName, requestedClaims);


          return isRequested;
        })
        .collect(Collectors.toList());


    return filteredDisclosures;
  }

  /**
   * 중첩 클레임 처리
   * 예: "address.street_address" 형태의 클레임 처리
   *
   * @param sdjwt SD-JWT 객체
   * @param nestedPaths 중첩 경로 집합
   * @return 중첩 클레임이 처리된 disclosure 목록
   */
  public static List<Disclosure> processNestedClaims(SDJWT sdjwt, Set<String> nestedPaths) {
    if (sdjwt == null || nestedPaths == null || nestedPaths.isEmpty()) {
      return Collections.emptyList();
    }

    List<Disclosure> nestedDisclosures = new ArrayList<>();

    for (String nestedPath : nestedPaths) {
      List<Object> path = DCQLPathProcessor.claimNameToPath(nestedPath);

      // 중첩 경로에 매치되는 disclosure 찾기
      List<Disclosure> matchingDisclosures = findDisclosuresForPath(sdjwt.getDisclosures(), path);
      nestedDisclosures.addAll(matchingDisclosures);
    }


    return nestedDisclosures;
  }

  /**
   * 배열 요소 선택적 공개
   * 예: "degrees[0].type", "degrees[*].university" 처리
   *
   * @param sdjwt SD-JWT 객체
   * @param arraySelections 배열 선택 정보 (배열 경로 -> 인덱스 목록)
   * @return 배열 요소 disclosure 목록
   */
  public static List<Disclosure> processArrayElements(SDJWT sdjwt, Map<String, List<Integer>> arraySelections) {
    if (sdjwt == null || arraySelections == null || arraySelections.isEmpty()) {
      return Collections.emptyList();
    }

    List<Disclosure> arrayDisclosures = new ArrayList<>();

    for (Map.Entry<String, List<Integer>> entry : arraySelections.entrySet()) {
      String arrayPath = entry.getKey();
      List<Integer> indices = entry.getValue();

      List<Disclosure> arrayElementDisclosures = findArrayElementDisclosures(
          sdjwt.getDisclosures(), arrayPath, indices);
      arrayDisclosures.addAll(arrayElementDisclosures);
    }


    return arrayDisclosures;
  }

  /**
   * 클레임 그룹별 처리
   * DCQL claim_sets 기능 지원
   *
   * @param sdjwt SD-JWT 객체
   * @param claimGroups 클레임 그룹 목록 (각 그룹은 대안적 선택)
   * @return 최적의 클레임 그룹에서 선택된 disclosure 목록
   */
  public static List<Disclosure> processClaimGroups(SDJWT sdjwt, List<Set<String>> claimGroups) {
    if (sdjwt == null || claimGroups == null || claimGroups.isEmpty()) {
      return Collections.emptyList();
    }

    // 첫 번째로 완전히 만족 가능한 그룹 선택
    for (Set<String> claimGroup : claimGroups) {
      List<Disclosure> groupDisclosures = filterDisclosures(sdjwt.getDisclosures(), claimGroup);

      if (areAllClaimsAvailable(claimGroup, groupDisclosures)) {
        return groupDisclosures;
      }
    }

    // 완전히 만족 가능한 그룹이 없으면 가장 많은 클레임을 만족하는 그룹 선택
    Set<String> bestGroup = claimGroups.stream()
        .max(Comparator.comparing(group ->
            filterDisclosures(sdjwt.getDisclosures(), group).size()))
        .orElse(Collections.emptySet());

    List<Disclosure> bestDisclosures = filterDisclosures(sdjwt.getDisclosures(), bestGroup);

    return bestDisclosures;
  }

  /**
   * 선택적 공개 통계 생성
   *
   * @param originalDisclosures 원본 disclosure 목록
   * @param filteredDisclosures 필터링된 disclosure 목록
   * @param requestedClaims 요청된 클레임 집합
   * @return 선택적 공개 통계
   */
  public static SelectiveDisclosureStats generateStats(List<Disclosure> originalDisclosures,
      List<Disclosure> filteredDisclosures,
      Set<String> requestedClaims) {
    int totalDisclosures = originalDisclosures != null ? originalDisclosures.size() : 0;
    int selectedDisclosures = filteredDisclosures != null ? filteredDisclosures.size() : 0;
    int requestedCount = requestedClaims != null ? requestedClaims.size() : 0;

    Set<String> availableClaims = originalDisclosures != null ?
        originalDisclosures.stream().map(Disclosure::getClaimName).collect(Collectors.toSet()) :
        Collections.emptySet();

    Set<String> selectedClaims = filteredDisclosures != null ?
        filteredDisclosures.stream().map(Disclosure::getClaimName).collect(Collectors.toSet()) :
        Collections.emptySet();

    Set<String> unsatisfiableClaims = requestedClaims != null ?
        requestedClaims.stream()
            .filter(claim -> !availableClaims.contains(claim))
            .collect(Collectors.toSet()) :
        Collections.emptySet();

    return new SelectiveDisclosureStats(
        totalDisclosures, selectedDisclosures, requestedCount,
        selectedClaims, unsatisfiableClaims
    );
  }

  // Private helper methods

  private static boolean isClaimRequested(String claimName, Set<String> requestedClaims) {
    if (claimName == null || requestedClaims == null) {
      return false;
    }

    // 정확한 매치
    if (requestedClaims.contains(claimName)) {
      return true;
    }

    // 와일드카드 패턴 매치 (예: "address.*")
    return requestedClaims.stream()
        .anyMatch(requested -> matchesPattern(claimName, requested));
  }

  private static boolean matchesPattern(String claimName, String pattern) {
    if (pattern.contains("*")) {
      String regex = pattern.replace("*", ".*");
      return claimName.matches(regex);
    }
    return claimName.equals(pattern);
  }

  private static List<Disclosure> findDisclosuresForPath(List<Disclosure> disclosures, List<Object> path) {
    // Path 기반 disclosure 매칭 로직
    // 현재는 단순 구현, 실제로는 더 복잡한 중첩 구조 처리 필요
    String pathClaimName = DCQLPathProcessor.pathToClaimName(path);

    return disclosures.stream()
        .filter(disclosure -> {
          String claimName = disclosure.getClaimName();
          return claimName != null && claimName.equals(pathClaimName);
        })
        .collect(Collectors.toList());
  }

  private static List<Disclosure> findArrayElementDisclosures(List<Disclosure> disclosures,
      String arrayPath,
      List<Integer> indices) {
    // 배열 요소 disclosure 매칭 로직
    // 현재는 단순 구현, 실제로는 배열 인덱스 기반 매칭 필요
    return disclosures.stream()
        .filter(disclosure -> {
          String claimName = disclosure.getClaimName();
          return claimName != null && claimName.startsWith(arrayPath);
        })
        .collect(Collectors.toList());
  }

  private static boolean areAllClaimsAvailable(Set<String> requestedClaims, List<Disclosure> disclosures) {
    Set<String> availableClaims = disclosures.stream()
        .map(Disclosure::getClaimName)
        .collect(Collectors.toSet());

    return availableClaims.containsAll(requestedClaims);
  }

  /**
   * 선택적 공개 통계 정보
   */
  public static class SelectiveDisclosureStats {
    private final int totalDisclosures;
    private final int selectedDisclosures;
    private final int requestedCount;
    private final Set<String> selectedClaims;
    private final Set<String> unsatisfiableClaims;

    public SelectiveDisclosureStats(int totalDisclosures, int selectedDisclosures, int requestedCount,
        Set<String> selectedClaims, Set<String> unsatisfiableClaims) {
      this.totalDisclosures = totalDisclosures;
      this.selectedDisclosures = selectedDisclosures;
      this.requestedCount = requestedCount;
      this.selectedClaims = selectedClaims != null ? selectedClaims : Collections.emptySet();
      this.unsatisfiableClaims = unsatisfiableClaims != null ? unsatisfiableClaims : Collections.emptySet();
    }

    public int getTotalDisclosures() { return totalDisclosures; }
    public int getSelectedDisclosures() { return selectedDisclosures; }
    public int getRequestedCount() { return requestedCount; }
    public Set<String> getSelectedClaims() { return selectedClaims; }
    public Set<String> getUnsatisfiableClaims() { return unsatisfiableClaims; }

    public double getSelectionRatio() {
      return totalDisclosures > 0 ? (double) selectedDisclosures / totalDisclosures : 0.0;
    }

    public boolean isFullySatisfiable() {
      return unsatisfiableClaims.isEmpty() && selectedDisclosures == requestedCount;
    }

    public String getSummary() {
      return String.format("Selected %d/%d disclosures (%.1f%%), %d unsatisfiable claims",
          selectedDisclosures, totalDisclosures, getSelectionRatio() * 100, unsatisfiableClaims.size());
    }
  }
}