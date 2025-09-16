package com.example.oid4vc.sdjwt.oid4vci;

import com.example.oid4vc.sdjwt.builder.SDJWTBuilder;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.exception.SDJWTException;
import com.example.oid4vc.sdjwt.jwt.JWSSigner;
import com.example.oid4vc.sdjwt.jwt.SignedJWT;
import com.example.oid4vc.sdjwt.jwt.crypto.ECDSASigner;
import com.example.oid4vc.sdjwt.jwt.crypto.RSASSASigner;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

/**
 * OID4VCIssuer provides convenient methods for issuing SD-JWT VCs
 * compatible with OpenID for Verifiable Credential Issuance.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class OID4VCIssuer {

  private final PrivateKey issuerPrivateKey;
  private final String issuerId;

  /**
   * Create a new OID4VC issuer.
   */
  public OID4VCIssuer(PrivateKey issuerPrivateKey, String issuerId) {
    if (issuerPrivateKey == null) {
      throw new IllegalArgumentException("Issuer private key cannot be null");
    }
    if (issuerId == null || issuerId.trim().isEmpty()) {
      throw new IllegalArgumentException("Issuer ID cannot be null or empty");
    }

    this.issuerPrivateKey = issuerPrivateKey;
    this.issuerId = issuerId;
  }

  /**
   * Issue an SD-JWT VC with standard claims.
   */
  public String issueCredential(String credentialType,
      Map<String, Object> subjectClaims,
      PublicKey holderPublicKey) throws SDJWTException {

    SDJWTBuilder builder = new SDJWTBuilder()
        .issuer(issuerId)
        .issuedAtNow()
        .expiresIn(365, ChronoUnit.DAYS)
        .verifiableCredentialType(credentialType);

    // Add holder public key for key binding
    if (holderPublicKey != null) {
      Map<String, Object> cnf = createConfirmationClaim(holderPublicKey);
      builder.confirmation(cnf);
    }

    // Add subject claims as selectively disclosable
    subjectClaims.forEach(builder::selectivelyDisclosableClaim);

    // Build with JWT signer
    SDJWT sdJwt = builder.build(this::signJWT);

    return sdJwt.toString();
  }

  /**
   * Issue an identity credential with standard personal information fields.
   */
  public String issueIdentityCredential(Map<String, Object> personalInfo,
      PublicKey holderPublicKey) throws SDJWTException {

    return issueCredential(
        "https://credentials.example.com/identity_credential",
        personalInfo,
        holderPublicKey
    );
  }

  /**
   * Create confirmation claim for holder public key.
   */
  private Map<String, Object> createConfirmationClaim(PublicKey holderPublicKey) {
    // This is a simplified implementation
    // In practice, you'd need to create a proper JWK representation
    return Map.of(
        "jwk", Map.of(
            "kty", getKeyType(holderPublicKey),
            "use", "sig"
            // Additional JWK parameters would go here
        )
    );
  }

  /**
   * Get key type for JWK.
   */
  private String getKeyType(PublicKey publicKey) {
    if (publicKey.getAlgorithm().equals("RSA")) {
      return "RSA";
    } else if (publicKey.getAlgorithm().equals("EC")) {
      return "EC";
    } else {
      throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
    }
  }

  /**
   * Sign JWT with the issuer's private key.
   */
  private String signJWT(String payloadJson) {
    try {
      // Determine algorithm and create signer
      String algorithm;
      JWSSigner signer;

      if (issuerPrivateKey instanceof RSAPrivateKey) {
        algorithm = "RS256";
        signer = new RSASSASigner((RSAPrivateKey) issuerPrivateKey);
      } else if (issuerPrivateKey instanceof ECPrivateKey) {
        algorithm = "ES256";
        signer = new ECDSASigner((ECPrivateKey) issuerPrivateKey);
      } else {
        throw new IllegalArgumentException("Unsupported private key type");
      }

      // Create header
      Map<String, Object> header = new HashMap<>();
      header.put("alg", algorithm);
      header.put("typ", "vc+sd-jwt");

      // Parse payload
      Map<String, Object> payloadMap = new ObjectMapper().readValue(payloadJson, new TypeReference<Map<String, Object>>() {});

      // Create and sign JWT
      SignedJWT signedJWT = new SignedJWT(header, payloadMap);
      signedJWT.sign(signer);

      return signedJWT.serialize();

    } catch (Exception e) {
      throw new SDJWTException("Failed to sign JWT", e);
    }
  }
}