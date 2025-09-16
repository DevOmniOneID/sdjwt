package com.example.oid4vc.sdjwt.jwt.crypto;

import com.example.oid4vc.sdjwt.jwt.JWSVerifier;
import com.example.oid4vc.sdjwt.jwt.SignedJWT;

import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

public class RSASSAVerifier implements JWSVerifier {

    private final RSAPublicKey publicKey;

    public RSASSAVerifier(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(SignedJWT signedJWT) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(signedJWT.getSigningInput().getBytes());
        return signature.verify(signedJWT.getSignatureBytes());
    }
}
