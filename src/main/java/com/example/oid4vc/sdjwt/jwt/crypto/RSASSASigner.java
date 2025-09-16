package com.example.oid4vc.sdjwt.jwt.crypto;

import com.example.oid4vc.sdjwt.jwt.JWSSigner;

import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;

public class RSASSASigner implements JWSSigner {

    private final RSAPrivateKey privateKey;

    public RSASSASigner(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] sign(String signingInput) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes());
        return signature.sign();
    }
}
