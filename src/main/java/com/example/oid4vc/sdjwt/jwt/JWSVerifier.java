package com.example.oid4vc.sdjwt.jwt;

public interface JWSVerifier {
    boolean verify(SignedJWT signedJWT) throws Exception;
}
