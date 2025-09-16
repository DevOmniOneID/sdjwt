package com.example.oid4vc.sdjwt.oid4vp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;

/**
 * VP Token Generator according to OpenID4VP 1.0 Appendix B
 * Supports W3C VC, JWT VC, and SD-JWT VC formats
 * 
 * Pure Java implementation without Spring dependencies for SDK compatibility
 */
public class VPTokenGenerator {

  private final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * Generate VP Token for W3C VC format
   * Based on Appendix B.1 - W3C Verifiable Credentials Data Model
   */
  public String generateW3CVPToken(String credentialId, JsonNode credential,
      String holderDid, String verifierClientId, String nonce) {
    try {
      // Create JWT Header
      ObjectNode header = objectMapper.createObjectNode();
      header.put("alg", "ES256");
      header.put("typ", "JWT");
      header.put("kid", holderDid + "#key-1");

      // Create JWT Payload with W3C VP
      ObjectNode payload = objectMapper.createObjectNode();
      payload.put("iss", holderDid);
      payload.put("aud", verifierClientId);
      payload.put("nonce", nonce);
      payload.put("iat", Instant.now().getEpochSecond());
      payload.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());

      // Create W3C Verifiable Presentation
      ObjectNode vp = createW3CVerifiablePresentation(credential, holderDid, verifierClientId, nonce);
      payload.set("vp", vp);

      // Encode JWT (mock signature for demo)
      String encodedHeader = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(header.toString().getBytes());
      String encodedPayload = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(payload.toString().getBytes());
      String mockSignature = "mock_es256_signature_" + System.currentTimeMillis();

      String jwtVP = encodedHeader + "." + encodedPayload + "." + mockSignature;

      // Create VP Token structure according to Section 8.1
      ObjectNode vpToken = objectMapper.createObjectNode();
      ArrayNode presentations = objectMapper.createArrayNode();
      presentations.add(jwtVP);
      vpToken.set(credentialId, presentations);

      return objectMapper.writeValueAsString(vpToken);

    } catch (Exception e) {
      throw new RuntimeException("VP Token generation failed", e);
    }
  }

  /**
   * Generate VP Token for JWT VC format
   * Based on Appendix B.2 - JWT Verifiable Credentials
   */
  public String generateJWTVCVPToken(String credentialId, String jwtVC,
      String holderDid, String verifierClientId, String nonce) {
    try {
      // Create JWT Header for VP
      ObjectNode header = objectMapper.createObjectNode();
      header.put("alg", "ES256");
      header.put("typ", "JWT");
      header.put("kid", holderDid + "#key-1");

      // Create JWT Payload for VP
      ObjectNode payload = objectMapper.createObjectNode();
      payload.put("iss", holderDid);
      payload.put("aud", verifierClientId);
      payload.put("nonce", nonce);
      payload.put("iat", Instant.now().getEpochSecond());
      payload.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());

      // Create JWT VC Verifiable Presentation
      ObjectNode vp = createJWTVCVerifiablePresentation(jwtVC, holderDid, verifierClientId, nonce);
      payload.set("vp", vp);

      // Encode JWT VP
      String encodedHeader = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(header.toString().getBytes());
      String encodedPayload = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(payload.toString().getBytes());
      String mockSignature = "mock_es256_signature_" + System.currentTimeMillis();

      String jwtVP = encodedHeader + "." + encodedPayload + "." + mockSignature;

      // Create VP Token structure
      ObjectNode vpToken = objectMapper.createObjectNode();
      ArrayNode presentations = objectMapper.createArrayNode();
      presentations.add(jwtVP);
      vpToken.set(credentialId, presentations);

      return objectMapper.writeValueAsString(vpToken);

    } catch (Exception e) {
      throw new RuntimeException("VP Token generation failed", e);
    }
  }

  private ObjectNode createW3CVerifiablePresentation(JsonNode credential,
      String holderDid, String verifierClientId, String nonce) {
    ObjectNode vp = objectMapper.createObjectNode();

    // @context
    ArrayNode context = objectMapper.createArrayNode();
    context.add("https://www.w3.org/ns/credentials/v2");
    vp.set("@context", context);

    // type
    ArrayNode type = objectMapper.createArrayNode();
    type.add("VerifiablePresentation");
    vp.set("type", type);

    // verifiableCredential
    ArrayNode verifiableCredentials = objectMapper.createArrayNode();
    verifiableCredentials.add(credential);
    vp.set("verifiableCredential", verifiableCredentials);

    // proof (Holder Binding)
    ObjectNode proof = objectMapper.createObjectNode();
    proof.put("type", "DataIntegrityProof");
    proof.put("cryptosuite", "ecdsa-rdfc-2019");
    proof.put("created", Instant.now().toString());
    proof.put("proofPurpose", "authentication");
    proof.put("verificationMethod", holderDid + "#key-1");
    proof.put("challenge", nonce); // Section 14.1.2 - nonce binding
    proof.put("domain", verifierClientId); // Section 14.1.2 - audience binding
    proof.put("proofValue", "mock_proof_value_" + System.currentTimeMillis());
    vp.set("proof", proof);

    return vp;
  }

  private ObjectNode createJWTVCVerifiablePresentation(String jwtVC,
      String holderDid, String verifierClientId, String nonce) {
    ObjectNode vp = objectMapper.createObjectNode();

    // @context
    ArrayNode context = objectMapper.createArrayNode();
    context.add("https://www.w3.org/ns/credentials/v2");
    vp.set("@context", context);

    // type
    ArrayNode type = objectMapper.createArrayNode();
    type.add("VerifiablePresentation");
    vp.set("type", type);

    // verifiableCredential (JWT format)
    ArrayNode verifiableCredentials = objectMapper.createArrayNode();
    verifiableCredentials.add(jwtVC);
    vp.set("verifiableCredential", verifiableCredentials);

    // proof (Holder Binding)
    ObjectNode proof = objectMapper.createObjectNode();
    proof.put("type", "DataIntegrityProof");
    proof.put("cryptosuite", "ecdsa-rdfc-2019");
    proof.put("created", Instant.now().toString());
    proof.put("proofPurpose", "authentication");
    proof.put("verificationMethod", holderDid + "#key-1");
    proof.put("challenge", nonce);
    proof.put("domain", verifierClientId);
    proof.put("proofValue", "mock_proof_value_" + System.currentTimeMillis());
    vp.set("proof", proof);

    return vp;
  }

  /**
   * Generate VP Token for SD-JWT VC format according to OpenID4VP 1.0
   * Enhanced version using sdjwt package utilities
   * 
   * @param credentialId Credential identifier from DCQL query  
   * @param sdJwtVC Original SD-JWT VC string
   * @param requestedClaims Set of claim names to disclose
   * @param holderPrivateKey Holder's private key for key binding JWT
   * @param verifierClientId Verifier's client ID (audience) 
   * @param nonce Nonce from authorization request
   * @return VP Token JSON string according to OID4VP 1.0
   */
  public String generateSDJWTVPToken(String credentialId, String sdJwtVC,
      Set<String> requestedClaims, PrivateKey holderPrivateKey,
      String verifierClientId, String nonce) {
    try {

      // Use the enhanced SDJWTVPTokenBuilder for consistent VP Token creation
      String vpToken = SDJWTVPTokenBuilder.createSimple(
          credentialId, sdJwtVC, holderPrivateKey, verifierClientId, nonce,
          requestedClaims.toArray(new String[0]));

      
      return vpToken;

    } catch (Exception e) {
      throw new RuntimeException("SD-JWT VP Token generation failed: " + e.getMessage(), e);
    }
  }

  /**
   * Generate VP Token for SD-JWT VC format with full disclosure
   * Enhanced with complete sdjwt utilities integration
   */
  public String generateFullSDJWTVPToken(String credentialId, String sdJwtVC,
      PrivateKey holderPrivateKey, String verifierClientId, String nonce) {
    try {

      // Use the enhanced SDJWTVPTokenBuilder for full disclosure
      String vpToken = SDJWTVPTokenBuilder.createFull(
          credentialId, sdJwtVC, holderPrivateKey, verifierClientId, nonce);

      return vpToken;

    } catch (Exception e) {
      throw new RuntimeException("Full SD-JWT VP Token generation failed: " + e.getMessage(), e);
    }
  }

  /**
   * Generate VP Token for SD-JWT VC format with minimal disclosure
   * Enhanced with complete sdjwt utilities integration
   */
  public String generateMinimalSDJWTVPToken(String credentialId, String sdJwtVC,
      PrivateKey holderPrivateKey, String verifierClientId, String nonce) {
    try {

      // Use the enhanced SDJWTVPTokenBuilder for minimal disclosure
      String vpToken = SDJWTVPTokenBuilder.createMinimal(
          credentialId, sdJwtVC, holderPrivateKey, verifierClientId, nonce);

      return vpToken;

    } catch (Exception e) {
      throw new RuntimeException("Minimal SD-JWT VP Token generation failed: " + e.getMessage(), e);
    }
  }

  /**
   * Generate VP Token with multiple presentations from claim sets
   * New method leveraging enhanced sdjwt utilities
   * 
   * @param credentialId Credential identifier
   * @param sdJwtVC SD-JWT VC string
   * @param claimSets List of different claim combinations
   * @param holderPrivateKey Holder's private key
   * @param verifierClientId Verifier's client ID
   * @param nonce Authorization request nonce
   * @return VP Token with multiple presentations
   */
  public String generateMultiplePresentationsSDJWTVPToken(String credentialId, String sdJwtVC,
      java.util.List<Set<String>> claimSets, PrivateKey holderPrivateKey,
      String verifierClientId, String nonce) {
    try {

      // Use the enhanced DCQLVPTokenGenerator for multiple presentations
      String vpToken = DCQLVPTokenGenerator.generateMultiplePresentations(
          credentialId, sdJwtVC, claimSets, holderPrivateKey, verifierClientId, nonce);

      return vpToken;

    } catch (Exception e) {
      throw new RuntimeException("Multiple presentations VP Token generation failed: " + e.getMessage(), e);
    }
  }
}