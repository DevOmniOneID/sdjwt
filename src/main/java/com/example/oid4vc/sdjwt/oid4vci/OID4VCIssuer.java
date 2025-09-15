package com.example.oid4vc.sdjwt.oid4vci;

import com.example.oid4vc.sdjwt.builder.SDJWTBuilder;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.temporal.ChronoUnit;
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
      PublicKey holderPublicKey) throws JOSEException {

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
      PublicKey holderPublicKey) throws JOSEException {

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
      JWSAlgorithm algorithm;
      JWSSigner signer;

      if (issuerPrivateKey instanceof RSAPrivateKey) {
        algorithm = JWSAlgorithm.RS256;
        signer = new RSASSASigner((RSAPrivateKey) issuerPrivateKey);
      } else if (issuerPrivateKey instanceof ECPrivateKey) {
        algorithm = JWSAlgorithm.ES256;
        signer = new ECDSASigner((ECPrivateKey) issuerPrivateKey);
      } else {
        throw new IllegalArgumentException("Unsupported private key type");
      }

      // Create header
      JWSHeader header = new JWSHeader.Builder(algorithm)
          .type(new com.nimbusds.jose.JOSEObjectType("vc+sd-jwt"))
          .build();

      // Parse payload
      Map<String, Object> payloadMap = JSONObjectUtils.parse(payloadJson);
      JWTClaimsSet claimsSet = JWTClaimsSet.parse(payloadMap);

      // Create and sign JWT
      SignedJWT signedJWT = new SignedJWT(header, claimsSet);
      signedJWT.sign(signer);

      return signedJWT.serialize();

    } catch (Exception e) {
      throw new RuntimeException("Failed to sign JWT", e);
    }
  }
}