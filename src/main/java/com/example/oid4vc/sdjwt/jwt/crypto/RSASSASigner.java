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
        
        byte[] signatureBytes = signature.sign();
        
        // For SD-JWT standard compliance, ensure consistent signature format
        // RSA signatures are typically already in the correct format (PKCS#1 v1.5)
        // but we validate the length matches the key size
        
        int keySize = privateKey.getModulus().bitLength();
        int expectedLength = keySize / 8;
        
        if (signatureBytes.length == expectedLength) {
            // Standard RSA signature format - correct length
            return signatureBytes;
        } else if (signatureBytes.length > expectedLength) {
            // Handle potential padding or wrapper - extract core signature
            return extractRSASignature(signatureBytes, expectedLength);
        } else {
            // Signature too short - pad with leading zeros if needed
            return padToExpectedLength(signatureBytes, expectedLength);
        }
    }

    /**
     * Extract RSA signature from potentially wrapped or padded data.
     * This handles cases where the signature might be DER-wrapped or have extra padding.
     *
     * @param signatureBytes Original signature bytes
     * @param expectedLength Expected signature length based on key size
     * @return Extracted RSA signature
     */
    private byte[] extractRSASignature(byte[] signatureBytes, int expectedLength) {
        // Check if it's DER-wrapped
        if (signatureBytes.length > expectedLength + 2 && signatureBytes[0] == 0x30) {
            // Try to extract from DER SEQUENCE
            try {
                int sequenceLength = signatureBytes[1] & 0xFF;
                int contentStart = 2;
                
                // Handle long form length
                if ((sequenceLength & 0x80) != 0) {
                    int lengthBytes = sequenceLength & 0x7F;
                    sequenceLength = 0;
                    for (int i = 0; i < lengthBytes; i++) {
                        sequenceLength = (sequenceLength << 8) | (signatureBytes[contentStart++] & 0xFF);
                    }
                }
                
                // Look for OCTET STRING or direct signature content
                if (contentStart < signatureBytes.length && signatureBytes[contentStart] == 0x04) {
                    // OCTET STRING - skip tag and length
                    contentStart++;
                    int octetLength = signatureBytes[contentStart++] & 0xFF;
                    if (octetLength == expectedLength && contentStart + octetLength <= signatureBytes.length) {
                        byte[] extracted = new byte[expectedLength];
                        System.arraycopy(signatureBytes, contentStart, extracted, 0, expectedLength);
                        return extracted;
                    }
                } else if (sequenceLength == expectedLength && contentStart + expectedLength <= signatureBytes.length) {
                    // Direct signature content
                    byte[] extracted = new byte[expectedLength];
                    System.arraycopy(signatureBytes, contentStart, extracted, 0, expectedLength);
                    return extracted;
                }
            } catch (Exception e) {
                // Fall through to trimming approach
            }
        }
        
        // Simple trimming approach - take the last expectedLength bytes
        // This handles cases with leading padding
        if (signatureBytes.length >= expectedLength) {
            byte[] trimmed = new byte[expectedLength];
            System.arraycopy(signatureBytes, signatureBytes.length - expectedLength, trimmed, 0, expectedLength);
            return trimmed;
        }
        
        // If still not the right length, return as-is and let verification handle it
        return signatureBytes;
    }

    /**
     * Pad signature to expected length with leading zeros.
     * This ensures consistent signature length for SD-JWT compliance.
     *
     * @param signatureBytes Original signature bytes
     * @param expectedLength Expected signature length
     * @return Padded signature
     */
    private byte[] padToExpectedLength(byte[] signatureBytes, int expectedLength) {
        byte[] padded = new byte[expectedLength];
        int paddingLength = expectedLength - signatureBytes.length;
        
        // Fill with leading zeros
        for (int i = 0; i < paddingLength; i++) {
            padded[i] = 0;
        }
        
        // Copy original signature
        System.arraycopy(signatureBytes, 0, padded, paddingLength, signatureBytes.length);
        
        return padded;
    }
}
