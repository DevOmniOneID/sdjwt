package org.omnione.did.oid4vc.core.jwt;

public interface JWSSigner {
    byte[] sign(String signingInput) throws Exception;
}
