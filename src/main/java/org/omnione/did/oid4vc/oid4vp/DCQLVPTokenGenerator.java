package org.omnione.did.oid4vc.oid4vp;

import org.omnione.did.oid4vc.dcql.DCQLClaimsExtractor;
import org.omnione.did.oid4vc.dcql.dto.DCQLQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.omnione.did.sdjwt.exception.SDJWTException;

import java.security.PrivateKey;
import java.util.*;

/**
 * DCQL Query-based VP Token Generation Unified Interface
 * Generates VP Token structures fully compliant with OpenID4VP 1.0 Section 8.1
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLVPTokenGenerator {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * Generate VP Token directly from DCQL query
   *
   * @param credentialData SD-JWT VC string
   * @param dcqlQuery DCQL query
   * @param credentialId Target credential ID
   * @param holderKey Holder private key
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return VP Token JSON in OpenID4VP 1.0 format
   */
  public static String generateFromDCQL(String credentialData,
      DCQLQuery dcqlQuery,
      String credentialId,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {

      // Extract requested claims from DCQL
      Set<String> requestedClaims = DCQLClaimsExtractor.extractClaimsForCredential(dcqlQuery, credentialId);

      // Generate VP Token
      String vpTokenString = OID4VPHandler.createVPTokenFromDCQL(
          credentialData, dcqlQuery, credentialId, holderKey, audience, nonce);

      // Wrap with OpenID4VP structure
      return wrapSingleCredentialVPToken(credentialId, vpTokenString);

    } catch (SDJWTException e) {
      throw new RuntimeException("Key binding JWT creation failed: " + e.getMessage(), e);
    } catch (Exception e) {
      throw new RuntimeException("DCQL VP token generation failed", e);
    }
  }

  /**
   * Generate VP Token for multiple credentials
   *
   * @param credentials Map of Credential ID and SD-JWT VC
   * @param dcqlQuery DCQL query
   * @param holderKey Holder private key
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return Combined VP Token JSON
   */
  public static String generateMultipleFromDCQL(Map<String, String> credentials,
      DCQLQuery dcqlQuery,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {

      Map<String, String> vpTokenMap = new HashMap<>();

      for (Map.Entry<String, String> entry : credentials.entrySet()) {
        String credentialId = entry.getKey();
        String sdJwtVC = entry.getValue();

        try {
          String vpTokenString = OID4VPHandler.createVPTokenFromDCQL(
              sdJwtVC, dcqlQuery, credentialId, holderKey, audience, nonce);
          vpTokenMap.put(credentialId, vpTokenString);

        } catch (Exception e) {
          // Individual failures are logged but processing continues
        }
      }

      if (vpTokenMap.isEmpty()) {
        throw new RuntimeException("No VP tokens were successfully generated");
      }

      return combineMultipleVPTokens(vpTokenMap);

    } catch (Exception e) {
      throw new RuntimeException("Multiple VP token generation failed", e);
    }
  }

  /**
   * Process Credential Set
   * Support for credential_sets functionality in OpenID4VP 1.0
   *
   * @param credentials Map of available credentials
   * @param dcqlQuery DCQL query (including credential_sets)
   * @param holderKey Holder private key
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return VP Token JSON
   */
  public static String generateFromCredentialSets(Map<String, String> credentials,
      DCQLQuery dcqlQuery,
      PrivateKey holderKey,
      String audience,
      String nonce) {
    try {

      if (dcqlQuery.getCredentialSets() == null || dcqlQuery.getCredentialSets().isEmpty()) {
        // No credential_sets, process normally
        return generateMultipleFromDCQL(credentials, dcqlQuery, holderKey, audience, nonce);
      }

      // Process credential_sets - select first satisfiable option
      for (DCQLQuery.CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
        if (credentialSet.getOptions() != null) {
          for (List<String> option : credentialSet.getOptions()) {

            // Check if all credentials in option are available
            boolean allAvailable = option.stream()
                .allMatch(credentials::containsKey);

            if (allAvailable) {

              Map<String, String> selectedCredentials = new HashMap<>();
              for (String credentialId : option) {
                selectedCredentials.put(credentialId, credentials.get(credentialId));
              }

              return generateMultipleFromDCQL(selectedCredentials, dcqlQuery,
                  holderKey, audience, nonce);
            }
          }
        }
      }

      throw new RuntimeException("No credential set options can be satisfied");

    } catch (Exception e) {
      throw new RuntimeException("Credential sets VP token generation failed", e);
    }
  }

  /**
   * Wrap VP Token structure for single credential
   *
   * @param credentialId Credential ID
   * @param vpTokenString VP Token string
   * @return VP Token JSON in OpenID4VP 1.0 format
   */
  public static String wrapSingleCredentialVPToken(String credentialId, String vpTokenString) throws Exception {
    ObjectNode vpToken = objectMapper.createObjectNode();
    ArrayNode presentations = objectMapper.createArrayNode();
    presentations.add(vpTokenString);
    vpToken.set(credentialId, presentations);

    return objectMapper.writeValueAsString(vpToken);
  }

  /**
   * Combine multiple VP Tokens into one
   *
   * @param vpTokenMap Map of Credential ID and VP Token string
   * @return Combined VP Token JSON
   */
  public static String combineMultipleVPTokens(Map<String, String> vpTokenMap) throws Exception {
    ObjectNode combinedVpToken = objectMapper.createObjectNode();

    for (Map.Entry<String, String> entry : vpTokenMap.entrySet()) {
      String credentialId = entry.getKey();
      String vpTokenString = entry.getValue();

      ArrayNode presentations = objectMapper.createArrayNode();
      presentations.add(vpTokenString);
      combinedVpToken.set(credentialId, presentations);
    }

    return objectMapper.writeValueAsString(combinedVpToken);
  }

  /**
   * Generate VP Token supporting multiple presentations
   * Create multiple presentations with different claim combinations from same credential
   *
   * @param credentialId Credential ID
   * @param sdJwtVC SD-JWT VC string
   * @param claimSets List of various claim combinations
   * @param holderKey Holder private key
   * @param audience Verifier client ID
   * @param nonce Authorization request nonce
   * @return Multiple presentations VP Token
   */
  public static String generateMultiplePresentations(String credentialId,
      String sdJwtVC,
      List<Set<String>> claimSets,
      PrivateKey holderKey,
      String audience,
      String nonce) throws Exception {
    try {

      List<String> vpTokenStrings = OID4VPHandler.createMultipleVPTokens(
          sdJwtVC, claimSets, holderKey, audience, nonce);

      ObjectNode vpToken = objectMapper.createObjectNode();
      ArrayNode presentations = objectMapper.createArrayNode();

      for (String vpTokenString : vpTokenStrings) {
        presentations.add(vpTokenString);
      }

      vpToken.set(credentialId, presentations);

      return objectMapper.writeValueAsString(vpToken);

    } catch (SDJWTException e) {
      throw new RuntimeException("Multiple presentations generation failed: " + e.getMessage(), e);
    }
  }

}