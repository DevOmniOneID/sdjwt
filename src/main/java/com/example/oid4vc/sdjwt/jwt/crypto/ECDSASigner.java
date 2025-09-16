package com.example.oid4vc.sdjwt.jwt.crypto;

import com.example.oid4vc.sdjwt.jwt.JWSSigner;

import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class ECDSASigner implements JWSSigner {

    private final ECPrivateKey privateKey;

    public ECDSASigner(ECPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public byte[] sign(String signingInput) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes());
        return signature.sign();
    }
}
