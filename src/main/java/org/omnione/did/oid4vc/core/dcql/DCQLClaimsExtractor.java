package org.omnione.did.oid4vc.core.dcql;

import org.omnione.did.oid4vc.core.dto.DCQLQuery;

import java.util.*;
import java.util.stream.Collectors;

/**
 * DCQL 쿼리에서 클레임 정보를 추출하는 유틸리티
 * OpenID4VP 1.0 Section 6 (DCQL) 규격에 따른 클레임 추출 처리
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLClaimsExtractor {

  /**
   * DCQL 쿼리에서 요청된 모든 클레임명을 추출
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @return 요청된 클레임명 집합
   */
  public static Set<String> extractClaimNames(DCQLQuery dcqlQuery) {
    if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
      return Collections.emptySet();
    }

    Set<String> allClaims = new HashSet<>();

    dcqlQuery.getCredentials().forEach(credential -> {
      if (credential.getClaims() != null) {
        credential.getClaims().forEach(claim -> {
          String claimName = DCQLPathProcessor.pathToClaimName(claim.getPath());
          if (claimName != null) {
            allClaims.add(claimName);
          }
        });
      }
    });

    return allClaims;
  }

  /**
   * DCQL 쿼리에서 Path 기반 클레임 추출 (JSON pointer 방식)
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @return 클레임 경로 집합
   */
  public static Set<String> extractClaimPaths(DCQLQuery dcqlQuery) {
    if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
      return Collections.emptySet();
    }

    Set<String> allPaths = new HashSet<>();

    dcqlQuery.getCredentials().forEach(credential -> {
      if (credential.getClaims() != null) {
        credential.getClaims().forEach(claim -> {
          String pathString = DCQLPathProcessor.pathToJsonPointer(claim.getPath());
          if (pathString != null) {
            allPaths.add(pathString);
          }
        });
      }
    });

    return allPaths;
  }

  /**
   * Credential별 클레임 매핑 추출
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @return Credential ID를 키로 하는 클레임 집합 맵
   */
  public static Map<String, Set<String>> extractCredentialClaims(DCQLQuery dcqlQuery) {
    if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
      return Collections.emptyMap();
    }

    Map<String, Set<String>> credentialClaimsMap = new HashMap<>();

    dcqlQuery.getCredentials().forEach(credential -> {
      String credentialId = credential.getId();
      Set<String> claims = new HashSet<>();

      if (credential.getClaims() != null) {
        credential.getClaims().forEach(claim -> {
          String claimName = DCQLPathProcessor.pathToClaimName(claim.getPath());
          if (claimName != null) {
            claims.add(claimName);
          }
        });
      }

      credentialClaimsMap.put(credentialId, claims);
    });

    return credentialClaimsMap;
  }

  /**
   * 특정 Credential ID의 클레임만 추출
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @param credentialId 대상 Credential ID
   * @return 해당 Credential의 클레임 집합
   */
  public static Set<String> extractClaimsForCredential(DCQLQuery dcqlQuery, String credentialId) {
    if (dcqlQuery == null || dcqlQuery.getCredentials() == null || credentialId == null) {
      return Collections.emptySet();
    }

    return dcqlQuery.getCredentials().stream()
        .filter(credential -> credentialId.equals(credential.getId()))
        .findFirst()
        .map(credential -> {
          if (credential.getClaims() == null) {
            return Collections.<String>emptySet();
          }

          return credential.getClaims().stream()
              .map(claim -> DCQLPathProcessor.pathToClaimName(claim.getPath()))
              .filter(Objects::nonNull)
              .collect(Collectors.toSet());
        })
        .orElse(Collections.emptySet());
  }

  /**
   * 중첩 경로 클레임 처리 (address.street_address)
   *
   * @param paths 경로 리스트들
   * @return 중첩 클레임명 집합
   */
  public static Set<String> extractNestedClaims(List<List<Object>> paths) {
    if (paths == null || paths.isEmpty()) {
      return Collections.emptySet();
    }

    return paths.stream()
        .map(DCQLPathProcessor::pathToClaimName)
        .filter(Objects::nonNull)
        .collect(Collectors.toSet());
  }

  /**
   * DCQL 쿼리에서 배열 요소 선택 정보 추출
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @return 배열 클레임과 인덱스 정보 맵
   */
  public static Map<String, List<Integer>> extractArraySelections(DCQLQuery dcqlQuery) {
    if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
      return Collections.emptyMap();
    }

    Map<String, List<Integer>> arraySelections = new HashMap<>();

    dcqlQuery.getCredentials().forEach(credential -> {
      if (credential.getClaims() != null) {
        credential.getClaims().forEach(claim -> {
          List<Object> path = claim.getPath();
          if (DCQLPathProcessor.containsArrayIndex(path)) {
            String arrayPath = DCQLPathProcessor.getArrayBasePath(path);
            List<Integer> indices = DCQLPathProcessor.extractArrayIndices(path);

            arraySelections.computeIfAbsent(arrayPath, k -> new ArrayList<>())
                .addAll(indices);
          }
        });
      }
    });

    return arraySelections;
  }

  /**
   * DCQL 쿼리의 클레임 요구사항 요약
   *
   * @param dcqlQuery DCQL 쿼리 객체
   * @return 클레임 요구사항 요약 정보
   */
  public static DCQLClaimsSummary summarizeClaims(DCQLQuery dcqlQuery) {
    Set<String> allClaims = extractClaimNames(dcqlQuery);
    Map<String, Set<String>> credentialClaims = extractCredentialClaims(dcqlQuery);
    Map<String, List<Integer>> arraySelections = extractArraySelections(dcqlQuery);

    return new DCQLClaimsSummary(allClaims, credentialClaims, arraySelections);
  }

  /**
   * DCQL 클레임 요구사항 요약 정보를 담는 클래스
   */
  public static class DCQLClaimsSummary {
    private final Set<String> allClaims;
    private final Map<String, Set<String>> credentialClaims;
    private final Map<String, List<Integer>> arraySelections;

    public DCQLClaimsSummary(Set<String> allClaims,
        Map<String, Set<String>> credentialClaims,
        Map<String, List<Integer>> arraySelections) {
      this.allClaims = allClaims != null ? allClaims : Collections.emptySet();
      this.credentialClaims = credentialClaims != null ? credentialClaims : Collections.emptyMap();
      this.arraySelections = arraySelections != null ? arraySelections : Collections.emptyMap();
    }

    public Set<String> getAllClaims() { return allClaims; }
    public Map<String, Set<String>> getCredentialClaims() { return credentialClaims; }
    public Map<String, List<Integer>> getArraySelections() { return arraySelections; }

    public int getTotalClaimsCount() { return allClaims.size(); }
    public int getCredentialCount() { return credentialClaims.size(); }
    public boolean hasArraySelections() { return !arraySelections.isEmpty(); }
  }
}