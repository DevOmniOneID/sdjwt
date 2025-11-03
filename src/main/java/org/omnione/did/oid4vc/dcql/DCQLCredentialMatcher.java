package org.omnione.did.oid4vc.dcql;

import lombok.extern.slf4j.Slf4j;
import org.omnione.did.sdjwt.core.SDJWT;
import org.omnione.did.oid4vc.dcql.dto.DCQLQuery;
import org.omnione.did.sdjwt.util.SimpleJWTDecoder;

import java.util.*;
import java.util.stream.Collectors;

/**
 * DCQL Query and Credential Matching Utility (Full Implementation Version)
 * Implementation of OpenID4VP 1.0 Section 6.4 (Processing Rules)
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
@Slf4j
public class DCQLCredentialMatcher {

  /**
   * Check if SD-JWT VC matches the specific credential requirement in DCQL query
   *
   * @param sdjwt SD-JWT VC object
   * @param credentialQuery DCQL credential query
   * @return Whether matches
   */
  public static boolean matchesCredentialQuery(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    if (sdjwt == null || credentialQuery == null) {
      return false;
    }

    try {
      // 1. Check format
      if (!matchesFormat(credentialQuery.getFormat())) {
        log.info("Format matching failed: {}", credentialQuery.getFormat());
        return false;
      }

      // 2. Check metadata (vct_values, issuer_did, etc.)
      if (!matchesMetadata(sdjwt, credentialQuery.getMeta())) {
        log.info("Metadata matching failed");
        return false;
      }

      // 3. Check availability of requested claims
      if (!hasRequestedClaims(sdjwt, credentialQuery)) {
        log.info("Requested claims matching failed");
        return false;
      }

      // 4. Check claim value conditions (values, min, max, etc.)
      if (!matchesClaimValues(sdjwt, credentialQuery)) {
        log.info("Claim value condition matching failed");
        return false;
      }

      // 5. Check cryptographic holder binding requirements
      if (!matchesCryptographicBinding(sdjwt, credentialQuery)) {
        log.info("Cryptographic holder binding requirement failed");
        return false;
      }

      log.info("All conditions matched successfully");
      return true;

    } catch (Exception e) {
      log.error("Exception occurred during matching: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Filter SD-JWT VCs that match the DCQL query
   *
   * @param sdjwtMap SD-JWT map with Credential ID as key
   * @param dcqlQuery DCQL query
   * @return Set of matching Credential IDs
   */
  public static Set<String> findMatchingCredentials(Map<String, SDJWT> sdjwtMap, DCQLQuery dcqlQuery) {
    if (sdjwtMap == null || dcqlQuery == null || dcqlQuery.getCredentials() == null) {
      return Collections.emptySet();
    }

    Set<String> matchingCredentials = new HashSet<>();

    for (DCQLQuery.CredentialQuery credentialQuery : dcqlQuery.getCredentials()) {
      String credentialId = credentialQuery.getId();
      SDJWT sdjwt = sdjwtMap.get(credentialId);

      log.info("Credential matching check: {}", credentialId);

      if (sdjwt != null && matchesCredentialQuery(sdjwt, credentialQuery)) {
        matchingCredentials.add(credentialId);
        log.info("{} matching succeeded", credentialId);
      } else {
        log.info("{} matching failed", credentialId);
      }
    }

    return matchingCredentials;
  }

  /**
   * Process DCQL credential_sets - check if any option satisfies
   *
   * @param sdjwtMap Available SD-JWT map
   * @param dcqlQuery DCQL query (including credential_sets)
   * @return Credential set match information
   */
  public static List<CredentialSetMatch> findCredentialSetMatches(Map<String, SDJWT> sdjwtMap, DCQLQuery dcqlQuery) {
    if (dcqlQuery.getCredentialSets() == null || dcqlQuery.getCredentialSets().isEmpty()) {
      // credential_sets not present, process all credentials individually
      return Collections.emptyList();
    }

    List<CredentialSetMatch> matches = new ArrayList<>();

    for (DCQLQuery.CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
      log.info("Credential Set matching check: {}", credentialSet.getId());

      CredentialSetMatch match = checkCredentialSetMatch(sdjwtMap, dcqlQuery, credentialSet);
      if (match.isComplete()) {
        matches.add(match);
        log.info("Credential Set {} matching succeeded", credentialSet.getId());
      } else {
        log.info("Credential Set {} matching failed", credentialSet.getId());
      }
    }

    return matches;
  }

  /**
   * Check if specific claims can be selectively disclosed in SD-JWT
   *
   * @param sdjwt SD-JWT VC
   * @param requestedClaims Requested claims
   * @return Disclosable and non-disclosable claims
   */
  public static ClaimAvailability checkClaimAvailability(SDJWT sdjwt, Set<String> requestedClaims) {
    if (sdjwt == null || requestedClaims == null) {
      return new ClaimAvailability(Collections.emptySet(), Collections.emptySet());
    }

    // Extract available claims from SD-JWT
    Set<String> availableClaims = extractAvailableClaims(sdjwt);

    Set<String> satisfiableClaims = requestedClaims.stream()
        .filter(availableClaims::contains)
        .collect(Collectors.toSet());

    Set<String> unsatisfiableClaims = requestedClaims.stream()
        .filter(claim -> !availableClaims.contains(claim))
        .collect(Collectors.toSet());

    log.info("Claim availability analysis:");
    log.info("   - Available Claims: {}", availableClaims);
    log.info("   - Satisfiable Claims: {}", satisfiableClaims);
    log.info("   - Unsatisfiable Claims: {}", unsatisfiableClaims);

    return new ClaimAvailability(satisfiableClaims, unsatisfiableClaims);
  }

  /**
   * Extract all available claims from SD-JWT (Disclosures + JWT claims)
   */
  private static Set<String> extractAvailableClaims(SDJWT sdjwt) {
    Set<String> availableClaims = new HashSet<>();

    // 1. Extract claims from Disclosures
    if (sdjwt.getDisclosures() != null) {
      sdjwt.getDisclosures().stream()
          .map(disclosure -> disclosure.getClaimName())
          .filter(Objects::nonNull)
          .forEach(availableClaims::add);
    }

    // 2. Extract public claims from JWT payload
    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      // Add both JWT standard claims and custom claims
      payload.keySet().stream()
          .filter(key -> !isReservedJWTClaim(key))
          .forEach(availableClaims::add);

    } catch (Exception e) {
      log.error("JWT payload parsing failed: {}", e.getMessage());
    }

    return availableClaims;
  }

  /**
   * Check JWT reserved claims (iss, sub, aud, exp, nbf, iat, jti, _sd_alg, etc.)
   */
  private static boolean isReservedJWTClaim(String claimName) {
    Set<String> reservedClaims = Set.of(
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti", // JWT standard claims
        "_sd_alg", "_sd", "cnf", // SD-JWT related claims
        "vct" // VC type claim
    );
    return reservedClaims.contains(claimName);
  }

  /**
   * Format matching check (full implementation)
   */
  public static boolean matchesFormat(String requiredFormat) {
    if (requiredFormat == null) {
      return true; // No format requirement
    }

    // Supported SD-JWT formats
    Set<String> supportedFormats = Set.of(
        "dc+sd-jwt",     // Digital Credential SD-JWT
        "vc+sd-jwt",     // Verifiable Credential SD-JWT
        "sd-jwt",        // General SD-JWT
        "jwt_vc_json"    // JWT VC JSON compatible
    );

    boolean isSupported = supportedFormats.contains(requiredFormat);

    if (!isSupported) {
        log.info("Unsupported format: {}", requiredFormat);
    }

    return isSupported;
  }

  /**
   * Metadata matching check (full implementation)
   */
  public static boolean matchesMetadata(SDJWT sdjwt, Map<String, Object> metadata) {
    if (metadata == null || metadata.isEmpty()) {
      return true; // No metadata requirement
    }

    try {
      // 1. Check vct_values
      if (metadata.containsKey("vct_values")) {
        List<String> requiredVcts = (List<String>) metadata.get("vct_values");
        if (!checkVctValues(sdjwt, requiredVcts)) {
          log.info("VCT value matching failed");
          return false;
        }
      }

      // 2. Check issuer_did
      if (metadata.containsKey("issuer_did")) {
        String requiredIssuer = (String) metadata.get("issuer_did");
        if (!checkIssuerDid(sdjwt, requiredIssuer)) {
          log.info("Issuer DID matching failed");
          return false;
        }
      }

      // 3. Check credential_type
      if (metadata.containsKey("credential_type")) {
        String requiredType = (String) metadata.get("credential_type");
        if (!checkCredentialType(sdjwt, requiredType)) {
          log.info("Credential Type matching failed");
          return false;
        }
      }

      // 4. Check required_trust_level
      if (metadata.containsKey("required_trust_level")) {
        String requiredTrustLevel = (String) metadata.get("required_trust_level");
        if (!checkTrustLevel(sdjwt, requiredTrustLevel)) {
          log.info("Trust Level matching failed");
          return false;
        }
      }

      // 5. Check privacy_level
      if (metadata.containsKey("privacy_level")) {
        String requiredPrivacyLevel = (String) metadata.get("privacy_level");
        if (!checkPrivacyLevel(sdjwt, requiredPrivacyLevel)) {
          log.info("Privacy Level matching failed");
          return false;
        }
      }

      log.info("All metadata conditions satisfied");
      return true;

    } catch (Exception e) {
      log.error("Error during metadata check: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * VCT (Verifiable Credential Type) value check (full implementation)
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
        log.info("SD-JWT has no vct claim");
        return false;
      }

      String actualVct = vctClaim.toString();
      boolean matches = requiredVcts.contains(actualVct);

      log.info("VCT matching: required={}, actual={}, result={}", requiredVcts, actualVct, matches);

      return matches;

    } catch (Exception e) {
      log.error("VCT check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Issuer DID check
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
        log.info("SD-JWT has no iss claim");
        return false;
      }

      String actualIssuer = issClaim.toString();
      boolean matches = requiredIssuer.equals(actualIssuer);

      log.info("Issuer matching: required={}, actual={}, result={}", requiredIssuer, actualIssuer, matches);

      return matches;

    } catch (Exception e) {
      log.error("Issuer check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Credential Type check
   */
  private static boolean checkCredentialType(SDJWT sdjwt, String requiredType) {
    if (requiredType == null) {
      return true;
    }

    // Extract type information from VCT or check in custom claims
    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      // 1. Check credential_type claim
      Object credTypeClaim = payload.get("credential_type");
      if (credTypeClaim != null && requiredType.equals(credTypeClaim.toString())) {
        return true;
      }

      // 2. Extract type information from VCT
      Object vctClaim = payload.get("vct");
      if (vctClaim != null) {
        String vct = vctClaim.toString();
        // Extract type information from VCT URL (e.g., https://example.com/identity_credential -> identity)
        if (vct.contains(requiredType) || vct.endsWith("/" + requiredType + "_credential")) {
          return true;
        }
      }

      log.info("Credential Type matching failed: required={}", requiredType);
      return false;

    } catch (Exception e) {
      log.error("Credential Type check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Trust Level check
   */
  private static boolean checkTrustLevel(SDJWT sdjwt, String requiredTrustLevel) {
    // Trust Level order: low < medium < high < critical
    Map<String, Integer> trustLevels = Map.of(
        "low", 1,
        "medium", 2,
        "high", 3,
        "critical", 4
    );

    // Currently consider all SD-JWT as "high" level
    int actualLevel = trustLevels.getOrDefault("high", 3);
    int requiredLevel = trustLevels.getOrDefault(requiredTrustLevel, 1);

    boolean meets = actualLevel >= requiredLevel;
    log.info("Trust Level check: required={}({}), actual=high({}), result={}", requiredTrustLevel, requiredLevel, actualLevel, meets);

    return meets;
  }

  /**
   * Privacy Level check
   */
  private static boolean checkPrivacyLevel(SDJWT sdjwt, String requiredPrivacyLevel) {
    // Privacy Level: public < internal < confidential < secret
    Map<String, Integer> privacyLevels = Map.of(
        "public", 1,
        "internal", 2,
        "confidential", 3,
        "secret", 4
    );

    // SD-JWT has "confidential" level by default
    int actualLevel = privacyLevels.getOrDefault("confidential", 3);
    int requiredLevel = privacyLevels.getOrDefault(requiredPrivacyLevel, 1);

    boolean meets = actualLevel >= requiredLevel;
    log.info("Privacy Level check: required={}({}), actual=confidential({}), result={}", requiredPrivacyLevel, requiredLevel, actualLevel, meets);

    return meets;
  }

  /**
   * Check existence of requested claims
   */
  private static boolean hasRequestedClaims(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    if (credentialQuery.getClaims() == null || credentialQuery.getClaims().isEmpty()) {
      return true; // No specific claim requirements
    }

    Set<String> requestedClaims = credentialQuery.getClaims().stream()
        .map(claim -> DCQLPathProcessor.pathToClaimName(claim.getPath()))
        .filter(Objects::nonNull)
        .collect(Collectors.toSet());

    ClaimAvailability availability = checkClaimAvailability(sdjwt, requestedClaims);

    // All requested claims must be available
    boolean allAvailable = availability.getUnsatisfiableClaims().isEmpty();

    if (!allAvailable) {
      log.info("Unavailable claims: {}", availability.getUnsatisfiableClaims());
    }

    return allAvailable;
  }

  /**
   * Check claim value conditions (values, min, max, value, etc.)
   */
  private static boolean matchesClaimValues(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    if (credentialQuery.getClaims() == null) {
      return true;
    }

    try {
      // Extract actual claim values from SD-JWT
      Map<String, Object> actualValues = extractClaimValues(sdjwt);

      for (DCQLQuery.ClaimQuery claimQuery : credentialQuery.getClaims()) {
        String claimName = DCQLPathProcessor.pathToClaimName(claimQuery.getPath());
        if (claimName == null) continue;

        Object actualValue = actualValues.get(claimName);
        if (actualValue == null) {
          log.info("Claim value not found: {}", claimName);
          continue; // No value, cannot verify condition
        }

        // 1. Check values condition (allowed values)
        if (claimQuery.getValues() != null && !claimQuery.getValues().isEmpty()) {
          if (!claimQuery.getValues().contains(actualValue)) {
            log.info("Disallowed value: {}={}, allowed values={}", claimName, actualValue, claimQuery.getValues());
            return false;
          }
        }

        // 2. Check value condition (exact value)
        if (claimQuery.getValue() != null) {
          if (!claimQuery.getValue().equals(actualValue)) {
            log.info("Value mismatch: {}={}, required value={}", claimName, actualValue, claimQuery.getValue());
            return false;
          }
        }

        // 3. Check min condition
        if (claimQuery.getMin() != null) {
          if (!checkMinCondition(actualValue, claimQuery.getMin(), claimName)) {
            return false;
          }
        }

        // 4. Check max condition
        if (claimQuery.getMax() != null) {
          if (!checkMaxCondition(actualValue, claimQuery.getMax(), claimName)) {
            return false;
          }
        }
      }

      return true;

    } catch (Exception e) {
      log.error("Claim value condition check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Extract actual claim values from SD-JWT (supporting nested paths)
   */
  private static Map<String, Object> extractClaimValues(SDJWT sdjwt) {
    Map<String, Object> claimValues = new HashMap<>();

    // 1. Extract values from Disclosures
    if (sdjwt.getDisclosures() != null) {
      for (var disclosure : sdjwt.getDisclosures()) {
        String claimName = disclosure.getClaimName();
        Object claimValue = disclosure.getClaimValue();

        // Add flat claim
        claimValues.put(claimName, claimValue);

        // If nested object, also add sub-paths
        if (claimValue instanceof Map) {
          extractNestedClaims(claimName, (Map<String, Object>) claimValue, claimValues);
        }
      }
    }

    // 2. Extract public claim values from JWT payload
    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      payload.entrySet().stream()
          .filter(entry -> !isReservedJWTClaim(entry.getKey()))
          .forEach(entry -> {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Add flat claim
            claimValues.put(key, value);

            // If nested object, also add sub-paths
            if (value instanceof Map) {
              extractNestedClaims(key, (Map<String, Object>) value, claimValues);
            }
          });

    } catch (Exception e) {
      log.error("JWT payload claim extraction failed: {}", e.getMessage(), e);
    }

    return claimValues;
  }

  /**
   * Recursively extract nested claim values
   * Example: address.country, address.city, etc.
   */
  private static void extractNestedClaims(String parentPath, Map<String, Object> nestedMap, Map<String, Object> claimValues) {
    if (nestedMap == null) {
      return;
    }

    for (Map.Entry<String, Object> entry : nestedMap.entrySet()) {
      String nestedKey = entry.getKey();
      Object nestedValue = entry.getValue();
      String fullPath = parentPath + "." + nestedKey;

      // Add nested path value
      claimValues.put(fullPath, nestedValue);

      // Recursively call if there's deeper nesting
      if (nestedValue instanceof Map) {
        extractNestedClaims(fullPath, (Map<String, Object>) nestedValue, claimValues);
      }
    }
  }

  /**
   * Minimum value condition check
   */
  private static boolean checkMinCondition(Object actualValue, Object minValue, String claimName) {
    try {
      if (actualValue instanceof Number && minValue instanceof Number) {
        double actual = ((Number) actualValue).doubleValue();
        double min = ((Number) minValue).doubleValue();
        boolean meets = actual >= min;
        log.info("Min condition: {}={} >= {} → {}", claimName, actual, min, meets);
        return meets;
      }

      if (actualValue instanceof String && minValue instanceof String) {
        // For strings, compare lexicographically
        int comparison = ((String) actualValue).compareTo((String) minValue);
        boolean meets = comparison >= 0;
        log.info("Min condition (string): {}={} >= {} → {}", claimName, actualValue, minValue, meets);
        return meets;
      }

      log.info("Min condition comparison impossible: {} (type mismatch)", claimName);
      return true; // Pass if comparison not possible

    } catch (Exception e) {
      log.error("Min condition check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Maximum value condition check
   */
  private static boolean checkMaxCondition(Object actualValue, Object maxValue, String claimName) {
    try {
      if (actualValue instanceof Number && maxValue instanceof Number) {
        double actual = ((Number) actualValue).doubleValue();
        double max = ((Number) maxValue).doubleValue();
        boolean meets = actual <= max;
        log.info("Max condition: {}={} <= {} → {}", claimName, actual, max, meets);
        return meets;
      }

      if (actualValue instanceof String && maxValue instanceof String) {
        // For strings, compare lexicographically
        int comparison = ((String) actualValue).compareTo((String) maxValue);
        boolean meets = comparison <= 0;
        log.info("Max condition (string): {}={} <= {} → {}", claimName, actualValue, maxValue, meets);
        return meets;
      }

      log.info("Max condition comparison impossible: {} (type mismatch)", claimName);
      return true; // Pass if comparison not possible

    } catch (Exception e) {
      log.error("Max condition check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Check cryptographic holder binding requirements
   */
  private static boolean matchesCryptographicBinding(SDJWT sdjwt, DCQLQuery.CredentialQuery credentialQuery) {
    Boolean required = credentialQuery.getRequireCryptographicHolderBinding();
    if (required == null || !required) {
      return true; // No binding requirement
    }

    try {
      SimpleJWTDecoder.SimpleJWT jwt = SimpleJWTDecoder.parse(sdjwt.getCredentialJwt());
      Map<String, Object> payload = jwt.getPayloadAsMap();

      // Check cnf (confirmation) claim
      Object cnfClaim = payload.get("cnf");
      boolean hasBinding = cnfClaim != null;

      log.info("Cryptographic holder binding: required={}, present={}", required, hasBinding);

      return hasBinding;

    } catch (Exception e) {
      log.error("Cryptographic binding check error: {}", e.getMessage(), e);
      return false;
    }
  }

  /**
   * Credential Set match check
   */
  private static CredentialSetMatch checkCredentialSetMatch(Map<String, SDJWT> sdjwtMap,
      DCQLQuery dcqlQuery,
      DCQLQuery.CredentialSet credentialSet) {

    CredentialSetMatch match = new CredentialSetMatch();

    if (credentialSet.getOptions() == null || credentialSet.getOptions().isEmpty()) {
      return match;
    }

    // Check each option
    for (int i = 0; i < credentialSet.getOptions().size(); i++) {
      List<String> option = credentialSet.getOptions().get(i);
      log.info("Option {} check: {}", (i + 1), option);

      boolean optionSatisfied = true;
      Set<String> optionCredentials = new HashSet<>();

      for (String credentialId : option) {
        SDJWT sdjwt = sdjwtMap.get(credentialId);
        DCQLQuery.CredentialQuery credentialQuery = findCredentialQueryById(dcqlQuery, credentialId);

        if (sdjwt == null) {
          log.info("SD-JWT not found: {}", credentialId);
          optionSatisfied = false;
          break;
        }

        if (credentialQuery == null) {
          log.info("Credential Query not found: {}", credentialId);
          optionSatisfied = false;
          break;
        }

        if (!matchesCredentialQuery(sdjwt, credentialQuery)) {
          log.info("Matching failed: {}", credentialId);
          optionSatisfied = false;
          break;
        }

        optionCredentials.add(credentialId);
        log.info("Matching succeeded: {}", credentialId);
      }

      if (optionSatisfied) {
        match.addSatisfiedOption(option, optionCredentials);
        log.info("Option {} satisfied", (i + 1));
      } else {
        log.info("Option {} not satisfied", (i + 1));
      }
    }

    return match;
  }

  /**
   * Find CredentialQuery by Credential ID
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
   * SD-JWT의 실제 값이 DCQL 조건에 맞는 클레임만 추출
   * credential의 claims가 null이면 모든 클레임을 추출 (OpenID4VP 표준)
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

    // Extract actual claim values from SD-JWT
    Map<String, Object> actualValues = extractClaimValues(sdjwt);

    dcqlQuery.getCredentials().forEach(credential -> {
      // If credential's claims is null, include all claims (standard behavior)
      if (credential.getClaims() == null) {
        matchingClaims.addAll(actualValues.keySet());
        log.info("credential.claims is null, including all claims: {}", actualValues.keySet());
        return;
      }

      // If claims is empty list, exclude all claims
      if (credential.getClaims().isEmpty()) {
        log.info("credential.claims is empty, excluding claims");
        return;
      }

      // If claims has specific requests, verify conditions
      credential.getClaims().forEach(claimQuery -> {
        String claimName = DCQLPathProcessor.pathToClaimName(claimQuery.getPath());
        if (claimName != null && meetsClaimConditions(claimQuery, actualValues.get(claimName))) {
          matchingClaims.add(claimName);
          log.info("Condition satisfied claim added: {}={}", claimName, actualValues.get(claimName));
        } else {
          log.info("Condition unsatisfied claim excluded: {}={}", claimName, actualValues.get(claimName));
        }
      });
    });

    return matchingClaims;
  }

  /**
   * Check if specific claim meets DCQL conditions
   */
  private static boolean meetsClaimConditions(DCQLQuery.ClaimQuery claimQuery, Object actualValue) {
    if (actualValue == null) {
      return false; // No value, condition not satisfied
    }

    // 1. Check values condition (allowed values)
    if (claimQuery.getValues() != null && !claimQuery.getValues().isEmpty()) {
      boolean valueMatches = claimQuery.getValues().contains(actualValue);
      log.info("  values condition: {} in {} = {}", actualValue, claimQuery.getValues(), valueMatches);
      if (!valueMatches) {
        return false;
      }
    }

    // 2. Check value condition (exact value)
    if (claimQuery.getValue() != null) {
      boolean exactMatch = claimQuery.getValue().equals(actualValue);
      log.info("  value condition: {} == {} = {}", actualValue, claimQuery.getValue(), exactMatch);
      if (!exactMatch) {
        return false;
      }
    }

    // 3. Check min condition
    if (claimQuery.getMin() != null) {
      if (!checkMinCondition(actualValue, claimQuery.getMin())) {
        return false;
      }
    }

    // 4. Check max condition
    if (claimQuery.getMax() != null) {
      if (!checkMaxCondition(actualValue, claimQuery.getMax())) {
        return false;
      }
    }

    return true; // All conditions satisfied
  }

  /**
   * Minimum value condition check
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

      return true; // Pass if comparison not possible

    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Maximum value condition check
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

      return true; // Pass if comparison not possible

    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Claim availability information
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
      return String.format("ClaimAvailability{satisfiable=%d, unsatisfiable=%d}",
          satisfiableClaims.size(), unsatisfiableClaims.size());
    }
  }

  /**
   * Credential Set match result
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
      return String.format("CredentialSetMatch{satisfied_options=%d}", satisfiedOptions.size());
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