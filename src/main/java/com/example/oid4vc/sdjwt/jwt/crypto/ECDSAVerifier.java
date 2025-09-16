package com.example.oid4vc.sdjwt.jwt.crypto;

import com.example.oid4vc.sdjwt.jwt.JWSVerifier;
import com.example.oid4vc.sdjwt.jwt.SignedJWT;

import java.security.Signature;
import java.security.interfaces.ECPublicKey;

public class ECDSAVerifier implements JWSVerifier {

    private final ECPublicKey publicKey;

    public ECDSAVerifier(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(SignedJWT signedJWT) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(signedJWT.getSigningInput().getBytes());
        return signature.verify(signedJWT.getSignatureBytes());
    }
}
