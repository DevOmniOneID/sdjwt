package com.example.oid4vc.sdjwt.jwt;

public interface JWSSigner {
    byte[] sign(String signingInput) throws Exception;
}
