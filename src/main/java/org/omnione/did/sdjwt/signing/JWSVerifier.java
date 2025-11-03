package org.omnione.did.sdjwt.signing;

public interface JWSVerifier {
    boolean verify(SignedJWT signedJWT) throws Exception;
}
