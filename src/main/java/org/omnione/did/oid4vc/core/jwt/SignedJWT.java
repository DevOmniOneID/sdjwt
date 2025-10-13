package org.omnione.did.oid4vc.core.jwt;

import org.omnione.did.oid4vc.core.util.Base64UrlUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

public class SignedJWT {

    private String header;
    private String payload;
    private String signature;
    private String originalString;

    private Map<String, Object> headerMap;
    private Map<String, Object> payloadMap;
    private byte[] signatureBytes;


    public SignedJWT(String header, String payload, String signature) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.originalString = header + "." + payload + "." + signature;
    }
    
    public SignedJWT(Map<String, Object> headerMap, Map<String, Object> payloadMap) throws JsonProcessingException {
        this.headerMap = headerMap;
        this.payloadMap = payloadMap;
        ObjectMapper mapper = new ObjectMapper();
        this.header = Base64UrlUtils.encode(mapper.writeValueAsBytes(headerMap));
        this.payload = Base64UrlUtils.encode(mapper.writeValueAsBytes(payloadMap));
    }

    public static SignedJWT parse(String jwtString) throws ParseException {
        String[] parts = jwtString.split("\\.");
        if (parts.length != 3) {
            throw new ParseException("Invalid JWT format", 0);
        }
        return new SignedJWT(parts[0], parts[1], parts[2]);
    }

    public Map<String, Object> getJWTClaimsSet() throws IOException {
        if (payloadMap == null) {
            byte[] decodedPayload = Base64UrlUtils.decode(payload);
            payloadMap = new ObjectMapper().readValue(decodedPayload, new TypeReference<Map<String, Object>>() {});
        }
        return payloadMap;
    }
    
    public Map<String, Object> getHeader() throws IOException {
        if (headerMap == null) {
            byte[] decodedHeader = Base64UrlUtils.decode(header);
            headerMap = new ObjectMapper().readValue(decodedHeader, new TypeReference<Map<String, Object>>() {});
        }
        return headerMap;
    }

    public String getSigningInput() {
        return header + "." + payload;
    }

    public byte[] getSignatureBytes() {
        if (signatureBytes == null && signature != null) {
            signatureBytes = Base64UrlUtils.decode(signature);
        }
        return signatureBytes;
    }

    public void sign(JWSSigner signer) throws Exception {
        this.signatureBytes = signer.sign(getSigningInput());
        this.signature = Base64UrlUtils.encode(this.signatureBytes);
        this.originalString = getSigningInput() + "." + this.signature;
    }

    public String serialize() {
        return originalString;
    }

    public boolean verify(JWSVerifier verifier) throws Exception {
        return verifier.verify(this);
    }
}
