package org.omnione.did.oid4vc.dcql;

import org.omnione.did.oid4vc.dcql.dto.DCQLQuery;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Utility for extracting claim information from DCQL query
 * Claim extraction processing according to OpenID4VP 1.0 Section 6 (DCQL) specification
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLClaimsExtractor {

  /**
   * Extract all requested claim names from DCQL query
   *
   * @param dcqlQuery DCQL query object
   * @return set of requested claim names
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
   * Extract path-based claims from DCQL query (JSON pointer format)
   *
   * @param dcqlQuery DCQL query object
   * @return set of claim paths
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
   * Extract claim mapping by Credential
   *
   * @param dcqlQuery DCQL query object
   * @return map with Credential ID as key and set of claims as value
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
   * Extract only claims for specific Credential ID
   *
   * @param dcqlQuery DCQL query object
   * @param credentialId target Credential ID
   * @return set of claims for the Credential
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
   * Handle nested path claims (address.street_address)
   *
   * @param paths list of paths
   * @return set of nested claim names
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
   * Extract array element selection information from DCQL query
   *
   * @param dcqlQuery DCQL query object
   * @return map with array claim and index information
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
   * Summarize claim requirements from DCQL query
   *
   * @param dcqlQuery DCQL query object
   * @return claim requirements summary information
   */
  public static DCQLClaimsSummary summarizeClaims(DCQLQuery dcqlQuery) {
    Set<String> allClaims = extractClaimNames(dcqlQuery);
    Map<String, Set<String>> credentialClaims = extractCredentialClaims(dcqlQuery);
    Map<String, List<Integer>> arraySelections = extractArraySelections(dcqlQuery);

    return new DCQLClaimsSummary(allClaims, credentialClaims, arraySelections);
  }

  /**
   * Class containing DCQL claim requirement summary information
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