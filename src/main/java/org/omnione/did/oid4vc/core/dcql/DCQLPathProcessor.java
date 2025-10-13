package org.omnione.did.oid4vc.core.dcql;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * DCQL Path 처리 전용 유틸리티
 * OpenID4VP 1.0 Section 7 (Claims Path Pointer) 구현
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLPathProcessor {

  /**
   * DCQL path array를 클레임명으로 변환
   * 예: ["address", "street_address"] -> "address.street_address"
   *
   * @param path DCQL path 배열
   * @return 클레임명 또는 null (유효하지 않은 경우)
   */
  public static String pathToClaimName(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return null;
    }

    try {
      List<String> pathParts = new ArrayList<>();

      for (Object element : path) {
        if (element == null) {
          // null은 배열의 모든 요소를 의미 (OpenID4VP Section 7.1)
          pathParts.add("*");
        } else if (element instanceof String) {
          pathParts.add((String) element);
        } else if (element instanceof Integer) {
          pathParts.add(String.valueOf(element));
        } else {
          return null;
        }
      }

      String claimName = String.join(".", pathParts);
      return claimName;

    } catch (Exception e) {
      return null;
    }
  }

  /**
   * DCQL path를 JSON Pointer 형식으로 변환
   * 예: ["address", "street_address"] -> "/address/street_address"
   *
   * @param path DCQL path 배열
   * @return JSON Pointer 문자열
   */
  public static String pathToJsonPointer(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return "";
    }

    try {
      StringBuilder pointer = new StringBuilder();

      for (Object element : path) {
        pointer.append("/");
        if (element == null) {
          pointer.append("*"); // 배열의 모든 요소
        } else if (element instanceof String) {
          pointer.append(escapeJsonPointer((String) element));
        } else if (element instanceof Integer) {
          pointer.append(element);
        } else {
          return null;
        }
      }

      return pointer.toString();

    } catch (Exception e) {
      return null;
    }
  }

  /**
   * 배열 인덱스를 포함한 경로 처리
   * 예: ["degrees", null, "type"] -> 모든 degrees 배열 요소의 type
   *
   * @param path DCQL path 배열
   * @return 처리된 클레임 경로 리스트
   */
  public static List<String> processArrayPath(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return Collections.emptyList();
    }

    // null이 포함된 경우 배열 처리
    if (path.contains(null)) {
      return processArrayPathWithNull(path);
    }

    // 일반적인 경로
    String claimName = pathToClaimName(path);
    return claimName != null ? List.of(claimName) : Collections.emptyList();
  }

  /**
   * Path 유효성 검증
   *
   * @param path 검증할 path
   * @return 유효한지 여부
   */
  public static boolean isValidPath(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return false;
    }

    for (Object element : path) {
      if (element != null &&
          !(element instanceof String) &&
          !(element instanceof Integer)) {
        return false;
      }
    }

    return true;
  }

  /**
   * 경로에 배열 인덱스(null 포함)가 있는지 확인
   *
   * @param path 확인할 path
   * @return 배열 인덱스 포함 여부
   */
  public static boolean containsArrayIndex(List<Object> path) {
    if (path == null) {
      return false;
    }

    return path.contains(null) || path.stream().anyMatch(e -> e instanceof Integer);
  }

  /**
   * 배열 경로에서 기본 경로 추출 (인덱스 제외)
   * 예: ["degrees", null, "type"] -> "degrees.type"
   *
   * @param path 원본 경로
   * @return 기본 경로
   */
  public static String getArrayBasePath(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return null;
    }

    List<Object> basePath = path.stream()
        .filter(element -> element != null && !(element instanceof Integer))
        .collect(Collectors.toList());

    return pathToClaimName(basePath);
  }

  /**
   * 배열 경로에서 인덱스 추출
   *
   * @param path 원본 경로
   * @return 인덱스 리스트
   */
  public static List<Integer> extractArrayIndices(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return Collections.emptyList();
    }

    return path.stream()
        .filter(element -> element instanceof Integer)
        .map(element -> (Integer) element)
        .collect(Collectors.toList());
  }

  /**
   * 클레임명을 경로로 역변환
   * 예: "address.street_address" -> ["address", "street_address"]
   *
   * @param claimName 클레임명
   * @return path 배열
   */
  public static List<Object> claimNameToPath(String claimName) {
    if (claimName == null || claimName.trim().isEmpty()) {
      return Collections.emptyList();
    }

    String[] parts = claimName.split("\\.");
    List<Object> path = new ArrayList<>();

    for (String part : parts) {
      if ("*".equals(part)) {
        path.add(null); // 배열의 모든 요소
      } else {
        try {
          // 숫자인지 확인
          int index = Integer.parseInt(part);
          path.add(index);
        } catch (NumberFormatException e) {
          // 문자열
          path.add(part);
        }
      }
    }

    return path;
  }

  private static List<String> processArrayPathWithNull(List<Object> path) {
    List<String> results = new ArrayList<>();

    // null을 * 으로 변환하여 배열 처리 표시
    List<Object> processedPath = path.stream()
        .map(element -> element == null ? "*" : element)
        .collect(Collectors.toList());

    String claimName = pathToClaimName(processedPath);
    if (claimName != null) {
      results.add(claimName);
    }

    return results;
  }

  private static String escapeJsonPointer(String value) {
    // JSON Pointer RFC 6901에 따른 이스케이프
    return value.replace("~", "~0").replace("/", "~1");
  }

  /**
   * 두 path가 같은 클레임을 참조하는지 확인
   *
   * @param path1 첫 번째 path
   * @param path2 두 번째 path
   * @return 같은 클레임 참조 여부
   */
  public static boolean isSameClaim(List<Object> path1, List<Object> path2) {
    if (path1 == null && path2 == null) {
      return true;
    }
    if (path1 == null || path2 == null) {
      return false;
    }

    String claim1 = pathToClaimName(path1);
    String claim2 = pathToClaimName(path2);

    return claim1 != null && claim1.equals(claim2);
  }
}