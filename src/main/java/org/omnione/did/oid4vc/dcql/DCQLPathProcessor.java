package org.omnione.did.oid4vc.dcql;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility for processing DCQL paths
 * Implementation of OpenID4VP 1.0 Section 7 (Claims Path Pointer)
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLPathProcessor {

  /**
   * Convert DCQL path array to claim name
   * Example: ["address", "street_address"] -> "address.street_address"
   *
   * @param path DCQL path array
   * @return claim name or null (if invalid)
   */
  public static String pathToClaimName(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return null;
    }

    try {
      List<String> pathParts = new ArrayList<>();

      for (Object element : path) {
        if (element == null) {
        // null means all elements of an array (OpenID4VP Section 7.1)
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
   * Convert DCQL path to JSON Pointer format
   * Example: ["address", "street_address"] -> "/address/street_address"
   *
   * @param path DCQL path array
   * @return JSON Pointer string
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
          pointer.append("*"); // all elements of array
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
   * Process path with array indices
   * Example: ["degrees", null, "type"] -> type of all degrees array elements
   *
   * @param path DCQL path array
   * @return processed claim path list
   */
  public static List<String> processArrayPath(List<Object> path) {
    if (path == null || path.isEmpty()) {
      return Collections.emptyList();
    }

    // Handle array processing when null is included
    if (path.contains(null)) {
      return processArrayPathWithNull(path);
    }

    // Generic path processing
    String claimName = pathToClaimName(path);
    return claimName != null ? List.of(claimName) : Collections.emptyList();
  }

  /**
   * Validate path validity
   *
   * @param path path to validate
   * @return whether valid
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
   * Check whether the path contains array indices (including null)
   *
   * @param path path to check
   * @return whether array indices are included
   */
  public static boolean containsArrayIndex(List<Object> path) {
    if (path == null) {
      return false;
    }

    return path.contains(null) || path.stream().anyMatch(e -> e instanceof Integer);
  }

  /**
   * Extract base path from array path (excluding indices)
   * Example: ["degrees", null, "type"] -> "degrees.type"
   *
   * @param path original path
   * @return base path
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
   * Extract indices from array path
   *
   * @param path original path
   * @return list of indices
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
   * Reverse transform claim name to path
   * Example: "address.street_address" -> ["address", "street_address"]
   *
   * @param claimName claim name
   * @return path array
   */
  public static List<Object> claimNameToPath(String claimName) {
    if (claimName == null || claimName.trim().isEmpty()) {
      return Collections.emptyList();
    }

    String[] parts = claimName.split("\\.");
    List<Object> path = new ArrayList<>();

    for (String part : parts) {
      if ("*".equals(part)) {
        path.add(null); // all elements of array
      } else {
        try {
          // check if numeric
          int index = Integer.parseInt(part);
          path.add(index);
        } catch (NumberFormatException e) {
          // string element
          path.add(part);
        }
      }
    }

    return path;
  }

  private static List<String> processArrayPathWithNull(List<Object> path) {
    List<String> results = new ArrayList<>();

    // Convert null to * to indicate array processing
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
    // Escape according to JSON Pointer RFC 6901
    return value.replace("~", "~0").replace("/", "~1");
  }

  /**
   * Check whether two paths reference the same claim
   *
   * @param path1 first path
   * @param path2 second path
   * @return whether they reference the same claim
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