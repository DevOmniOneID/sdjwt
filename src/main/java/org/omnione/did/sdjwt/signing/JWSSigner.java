package org.omnione.did.sdjwt.signing;

public interface JWSSigner {
    byte[] sign(String signingInput) throws Exception;
}
