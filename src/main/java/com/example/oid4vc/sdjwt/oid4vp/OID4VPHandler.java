package com.example.oid4vc.sdjwt.oid4vp;

import com.example.oid4vc.sdjwt.core.Disclosure;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.keybinding.KeyBindingJWTBuilder;
import com.example.oid4vc.sdjwt.processor.SelectiveDisclosureProcessor;
import com.example.oid4vc.sdjwt.dcql.DCQLClaimsExtractor;
import com.example.oid4vc.sdjwt.dto.DCQLQuery;
import com.nimbusds.jose.JOSEException;
import com.example.oid4vc.sdjwt.exception.SDJWTException;
import lombok.extern.slf4j.Slf4j;

import java.security.PrivateKey;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * OID4VPHandler provides utilities for creating VP tokens from SD-JWT VCs
 * according to OpenID for Verifiable Presentations 1.0 specification.
 *
 * This class implements the requirements from:
 * - OpenID4VP 1.0 Section 8.1 (VP Token structure)
 * - OpenID4VP 1.0 Section 14.1.2 (Replay attack prevention)
 * - IETF SD-JWT VC specification for selective disclosure
 *
 * Enhanced version with DCQL integration and advanced processing capabilities.
 *
 * @author OmniOne Open DID
 * @version 2.0
 * @since 1.0
 */
@Slf4j
public class OID4VPHandler {

  /**
   * Create a VP token with selective disclosure according to OpenID4VP 1.0.
   *
   * This method creates a VP token that includes only the requested claims
   * and binds it to the verifier (audience) and transaction (nonce) as required
   * by OpenID4VP 1.0 Section 14.1.2 for replay attack prevention.
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param requestedClaims Set of claim names to disclose (from DCQL claims)
   * @param holderPrivateKey Holder's private key for key binding JWT
   * @param audience Verifier's client ID (bound to key binding JWT)
   * @param nonce Nonce from authorization request (bound to key binding JWT)
   * @return SD-JWT VP token string in format: JWT~Disclosure1~Disclosure2~...~KeyBindingJWT
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static String createVPToken(String sdJwtVC,
      Set<String> requestedClaims,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.debug("Creating VP token with selective disclosure for {} claims", requestedClaims.size());

    // 1. Parse the SD-JWT VC
    SDJWT originalSDJWT = SDJWT.parse(sdJwtVC);
    log.debug("Parsed SD-JWT VC with {} disclosures", originalSDJWT.getDisclosures().size());

    // 2. Filter disclosures based on requested claims using enhanced processor
    List<Disclosure> selectedDisclosures = SelectiveDisclosureProcessor.filterDisclosures(
        originalSDJWT.getDisclosures(), requestedClaims);

    log.info("Selected {} out of {} disclosures for VP token",
        selectedDisclosures.size(), originalSDJWT.getDisclosures().size());

    // 3. Create filtered SD-JWT (without key binding initially)
    SDJWT filteredSDJWT = new SDJWT(
        originalSDJWT.getCredentialJwt(),
        selectedDisclosures
    );

    // 4. Prepare SD-JWT string for hash calculation (IETF SD-JWT compliant)
    String sdJwtForHash = filteredSDJWT.getCredentialJwt() + "~" + 
        selectedDisclosures.stream()
            .map(Disclosure::getDisclosure)
            .collect(Collectors.joining("~")) + "~";

    // 5. Create key binding JWT according to OpenID4VP 1.0 Section 14.1.2 with sd_hash
    // Binds the VP to the intended audience (client_id) and transaction (nonce)
    // sd_hash ensures the Key Binding JWT is cryptographically bound to this specific SD-JWT
    String keyBindingJWT = KeyBindingJWTBuilder.createKeyBindingJWT(
        holderPrivateKey, audience, nonce, sdJwtForHash);

    // 6. Add key binding to SD-JWT to complete VP token
    SDJWT finalSDJWT = new SDJWT(
        filteredSDJWT.getCredentialJwt(),
        filteredSDJWT.getDisclosures(),
        keyBindingJWT
    );

    String vpToken = finalSDJWT.toString();
    log.info("Created VP token with key binding for audience: {}", audience);

    return vpToken;
  }

  /**
   * Create a VP token from DCQL query
   * Enhanced method that processes DCQL query directly
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param dcqlQuery DCQL query object
   * @param credentialId Target credential ID from DCQL
   * @param holderPrivateKey Holder's private key
   * @param audience Verifier's client ID
   * @param nonce Authorization request nonce
   * @return SD-JWT VP token string
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static String createVPTokenFromDCQL(String sdJwtVC,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.debug("Creating VP token from DCQL query for credential: {}", credentialId);

    // Extract requested claims from DCQL for specific credential
    Set<String> requestedClaims = DCQLClaimsExtractor.extractClaimsForCredential(dcqlQuery, credentialId);

    if (requestedClaims.isEmpty()) {
      log.info("No specific claims requested in DCQL for credential {}, creating minimal disclosure", credentialId);
      return createMinimalVPToken(sdJwtVC, holderPrivateKey, audience, nonce);
    }

    return createVPToken(sdJwtVC, requestedClaims, holderPrivateKey, audience, nonce);
  }

  /**
   * Create a VP token with advanced DCQL processing
   * Supports claim_sets, array selections, and nested claims
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param dcqlQuery DCQL query with advanced features
   * @param credentialId Target credential ID
   * @param holderPrivateKey Holder's private key
   * @param audience Verifier's client ID
   * @param nonce Authorization request nonce
   * @return SD-JWT VP token string
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static String createAdvancedVPTokenFromDCQL(String sdJwtVC,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.debug("Creating advanced VP token from DCQL query for credential: {}", credentialId);

    // 1. Parse original SD-JWT
    SDJWT originalSDJWT = SDJWT.parse(sdJwtVC);

    // 2. Process DCQL with advanced features
    SDJWT processedSDJWT = SelectiveDisclosureProcessor.processSelectiveDisclosure(
        sdJwtVC, dcqlQuery, credentialId);

    if (processedSDJWT == null) {
      log.warn("DCQL processing failed for credential {}, falling back to minimal disclosure", credentialId);
      return createMinimalVPToken(sdJwtVC, holderPrivateKey, audience, nonce);
    }

    // 3. Prepare SD-JWT string for hash calculation (IETF SD-JWT compliant)
    String sdJwtForHash = processedSDJWT.getCredentialJwt() + "~" + 
        processedSDJWT.getDisclosures().stream()
            .map(Disclosure::getDisclosure)
            .collect(Collectors.joining("~")) + "~";

    // 4. Create key binding JWT with sd_hash
    String keyBindingJWT = KeyBindingJWTBuilder.createKeyBindingJWT(
        holderPrivateKey, audience, nonce, sdJwtForHash);

    // 4. Add key binding to processed SD-JWT
    SDJWT finalSDJWT = new SDJWT(
        processedSDJWT.getCredentialJwt(),
        processedSDJWT.getDisclosures(),
        keyBindingJWT
    );

    String vpToken = finalSDJWT.toString();
    log.info("Created advanced VP token with {} disclosures for credential: {}",
        processedSDJWT.getDisclosures().size(), credentialId);

    return vpToken;
  }

  /**
   * Create a VP token disclosing all claims.
   * Includes all available selective disclosures from the original SD-JWT VC.
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param holderPrivateKey Holder's private key for key binding JWT
   * @param audience Verifier's client ID
   * @param nonce Nonce from authorization request
   * @return Complete SD-JWT VP token with all disclosures
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static String createFullVPToken(String sdJwtVC,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.debug("Creating full disclosure VP token");

    SDJWT originalSDJWT = SDJWT.parse(sdJwtVC);

    // Get all claim names for full disclosure
    Set<String> allClaims = originalSDJWT.getDisclosures().stream()
        .map(Disclosure::getClaimName)
        .collect(Collectors.toSet());

    log.info("Creating full VP token with {} claims", allClaims.size());

    return createVPToken(sdJwtVC, allClaims, holderPrivateKey, audience, nonce);
  }

  /**
   * Create a VP token with minimal disclosure.
   * Only includes the mandatory claims in the JWT (no selective disclosures).
   * This is useful for use cases requiring minimum data exposure.
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param holderPrivateKey Holder's private key for key binding JWT
   * @param audience Verifier's client ID
   * @param nonce Nonce from authorization request
   * @return Minimal SD-JWT VP token with no disclosures
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static String createMinimalVPToken(String sdJwtVC,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.debug("Creating minimal disclosure VP token");
    log.info("Creating minimal VP token with no selective disclosures");

    // Create VP with empty set (no disclosures, only mandatory claims in JWT)
    return createVPToken(sdJwtVC, Set.of(), holderPrivateKey, audience, nonce);
  }

  /**
   * Create multiple VP tokens from a single SD-JWT VC with different disclosure sets.
   * This method supports the OpenID4VP 1.0 capability to have multiple presentations
   * of the same credential with different claim sets in a single VP token response.
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param claimSets List of claim sets, each representing different disclosure requirements
   * @param holderPrivateKey Holder's private key for key binding JWT
   * @param audience Verifier's client ID
   * @param nonce Nonce from authorization request
   * @return List of VP token strings, one for each claim set
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static List<String> createMultipleVPTokens(String sdJwtVC,
      List<Set<String>> claimSets,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.info("Creating {} VP tokens with different disclosure sets", claimSets.size());

    return claimSets.stream()
        .map(claimSet -> {
          try {
            return createVPToken(sdJwtVC, claimSet, holderPrivateKey, audience, nonce);
          } catch (SDJWTException e) {
            log.error("Failed to create VP token for claim set: {}", claimSet, e);
            throw new RuntimeException("VP token creation failed", e);
          }
        })
        .collect(Collectors.toList());
  }

  /**
   * Create VP token with claim groups processing
   * Supports OpenID4VP claim_sets feature for alternative claim combinations
   *
   * @param sdJwtVC Original SD-JWT VC string
   * @param claimGroups List of alternative claim groups
   * @param holderPrivateKey Holder's private key
   * @param audience Verifier's client ID
   * @param nonce Authorization request nonce
   * @return VP token with optimal claim group selection
   * @throws SDJWTException if key binding JWT creation fails
   */
  public static String createVPTokenWithClaimGroups(String sdJwtVC,
      List<Set<String>> claimGroups,
      PrivateKey holderPrivateKey,
      String audience,
      String nonce) throws SDJWTException {

    log.debug("Creating VP token with {} claim groups", claimGroups.size());

    // 1. Parse original SD-JWT
    SDJWT originalSDJWT = SDJWT.parse(sdJwtVC);

    // 2. Process claim groups to find optimal selection
    List<Disclosure> selectedDisclosures = SelectiveDisclosureProcessor.processClaimGroups(
        originalSDJWT, claimGroups);

    // 3. Create filtered SD-JWT
    SDJWT filteredSDJWT = new SDJWT(
        originalSDJWT.getCredentialJwt(),
        selectedDisclosures
    );

    // 4. Prepare SD-JWT string for hash calculation (IETF SD-JWT compliant)
    String sdJwtForHash = filteredSDJWT.getCredentialJwt() + "~" + 
        selectedDisclosures.stream()
            .map(Disclosure::getDisclosure)
            .collect(Collectors.joining("~")) + "~";

    // 5. Create key binding JWT with sd_hash
    String keyBindingJWT = KeyBindingJWTBuilder.createKeyBindingJWT(
        holderPrivateKey, audience, nonce, sdJwtForHash);

    // 6. Add key binding to complete VP token
    SDJWT finalSDJWT = new SDJWT(
        filteredSDJWT.getCredentialJwt(),
        filteredSDJWT.getDisclosures(),
        keyBindingJWT
    );

    String vpToken = finalSDJWT.toString();
    log.info("Created VP token with {} disclosures from claim groups", selectedDisclosures.size());

    return vpToken;
  }

  /**
   * Validate SD-JWT VC for VP token creation
   *
   * @param sdJwtVC SD-JWT VC string to validate
   * @return validation result
   */
  public static VPTokenValidationResult validateForVPToken(String sdJwtVC) {
    if (sdJwtVC == null || sdJwtVC.trim().isEmpty()) {
      return VPTokenValidationResult.invalid("SD-JWT VC is null or empty");
    }

    try {
      SDJWT sdjwt = SDJWT.parse(sdJwtVC);

      // Basic validation checks
      if (sdjwt.getCredentialJwt() == null) {
        return VPTokenValidationResult.invalid("SD-JWT VC has no credential JWT");
      }

      if (sdjwt.getDisclosures() == null) {
        return VPTokenValidationResult.invalid("SD-JWT VC has no disclosures");
      }

      log.debug("SD-JWT VC validation successful: {} disclosures available",
          sdjwt.getDisclosures().size());

      return VPTokenValidationResult.valid(
          "Valid SD-JWT VC with " + sdjwt.getDisclosures().size() + " disclosures");

    } catch (Exception e) {
      log.error("SD-JWT VC validation failed", e);
      return VPTokenValidationResult.invalid("SD-JWT VC parsing failed: " + e.getMessage());
    }
  }

  /**
   * VP Token validation result
   */
  public static class VPTokenValidationResult {
    private final boolean valid;
    private final String message;

    private VPTokenValidationResult(boolean valid, String message) {
      this.valid = valid;
      this.message = message;
    }

    public static VPTokenValidationResult valid(String message) {
      return new VPTokenValidationResult(true, message);
    }

    public static VPTokenValidationResult invalid(String message) {
      return new VPTokenValidationResult(false, message);
    }

    public boolean isValid() { return valid; }
    public String getMessage() { return message; }
  }
}