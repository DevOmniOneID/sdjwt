package org.omnione.did.oid4vc.core.jwt;

public interface JWSVerifier {
    boolean verify(SignedJWT signedJWT) throws Exception;
}
