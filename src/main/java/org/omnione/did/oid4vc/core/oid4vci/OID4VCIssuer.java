package org.omnione.did.oid4vc.core.oid4vci;

import org.omnione.did.oid4vc.sdjwt.builder.SDJWTBuilder;
import org.omnione.did.oid4vc.sdjwt.core.SDJWT;
import org.omnione.did.oid4vc.sdjwt.exception.SDJWTException;
import org.omnione.did.oid4vc.core.jwt.JWSSigner;
import org.omnione.did.oid4vc.core.jwt.SignedJWT;
import org.omnione.did.oid4vc.core.jwt.crypto.ECDSASigner;
import org.omnione.did.oid4vc.core.jwt.crypto.RSASSASigner;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.omnione.did.wallet.key.WalletManagerInterface;
import org.omnione.did.wallet.exception.WalletException;

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
  private final WalletManagerInterface walletManager;
  private final String keyId;
  private final String issuerId;

  /**
   * Create a new OID4VC issuer with PrivateKey.
   */
  public OID4VCIssuer(PrivateKey issuerPrivateKey, String issuerId) {
    if (issuerPrivateKey == null) {
      throw new IllegalArgumentException("Issuer private key cannot be null");
    }
    if (issuerId == null || issuerId.trim().isEmpty()) {
      throw new IllegalArgumentException("Issuer ID cannot be null or empty");
    }

    this.issuerPrivateKey = issuerPrivateKey;
    this.walletManager = null;
    this.keyId = null;
    this.issuerId = issuerId;
  }

  /**
   * Create a new OID4VC issuer with WalletManagerInterface.
   */
  public OID4VCIssuer(WalletManagerInterface walletManager, String keyId, String issuerId) {
    if (walletManager == null) {
      throw new IllegalArgumentException("Wallet manager cannot be null");
    }
    if (keyId == null || keyId.trim().isEmpty()) {
      throw new IllegalArgumentException("Key ID cannot be null or empty");
    }
    if (issuerId == null || issuerId.trim().isEmpty()) {
      throw new IllegalArgumentException("Issuer ID cannot be null or empty");
    }

    this.issuerPrivateKey = null;
    this.walletManager = walletManager;
    this.keyId = keyId;
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
   * Sign JWT with the issuer's private key or wallet manager.
   */
  private String signJWT(String payloadJson) {
    try {
      if (walletManager != null) {
        // Use WalletManager for signing
        return signJWTWithWalletManager(payloadJson);
      } else {
        // Use PrivateKey for signing (existing logic)
        return signJWTWithPrivateKey(payloadJson);
      }
    } catch (Exception e) {
      throw new SDJWTException("Failed to sign JWT", e);
    }
  }

  /**
   * Sign JWT using WalletManager.
   */
  private String signJWTWithWalletManager(String payloadJson) throws Exception {
    try {
      // Get algorithm from wallet manager
      String keyAlgorithm = walletManager.getKeyAlgorithm(keyId);
      String algorithm;
      JWSSigner signer;
      
      // Determine JWS algorithm and create signer based on key algorithm
      if (keyAlgorithm.contains("RSA")) {
        algorithm = "RS256";
        // Note: RSASSASigner with WalletManager constructor would be needed
        throw new IllegalArgumentException("RSA with WalletManager not yet implemented");
      } else if (keyAlgorithm.contains("Secp256r1") || keyAlgorithm.contains("SECP256r1") || 
                 keyAlgorithm.contains("Secp256k1") || keyAlgorithm.contains("SECP256k1") || 
                 keyAlgorithm.contains("EC")) {
        algorithm = keyAlgorithm.contains("Secp256k1") || keyAlgorithm.contains("SECP256k1") ? "ES256K" : "ES256";
        signer = new ECDSASigner(walletManager, keyId);
      } else {
        throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
      }

      // Create header
      Map<String, Object> header = new HashMap<>();
      header.put("alg", algorithm);
      header.put("typ", "vc+sd-jwt");

      // Parse payload
      Map<String, Object> payloadMap = new ObjectMapper().readValue(payloadJson, new TypeReference<Map<String, Object>>() {});

      // Create and sign JWT using the signer
      SignedJWT signedJWT = new SignedJWT(header, payloadMap);
      signedJWT.sign(signer);

      return signedJWT.serialize();

    } catch (WalletException e) {
      throw new SDJWTException("Failed to sign with wallet manager", e);
    }
  }

  /**
   * Sign JWT using PrivateKey (existing logic).
   */
  private String signJWTWithPrivateKey(String payloadJson) throws Exception {
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
  }
}