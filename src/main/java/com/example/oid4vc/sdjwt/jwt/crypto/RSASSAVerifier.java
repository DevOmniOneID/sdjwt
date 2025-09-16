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
        
        byte[] signatureBytes = signedJWT.getSignatureBytes();
        
        // For SD-JWT standard compliance, expect consistent RSA signature format
        // RSA signatures should match the key size (PKCS#1 v1.5 padding)
        
        int keySize = publicKey.getModulus().bitLength();
        int expectedSignatureLength = keySize / 8;
        
        if (signatureBytes.length == expectedSignatureLength) {
            // Standard RSA signature format - verify directly
            return signature.verify(signatureBytes);
        } else if (signatureBytes.length < expectedSignatureLength) {
            // Handle potential missing leading zeros - pad and verify
            byte[] paddedSignature = padToExpectedLength(signatureBytes, expectedSignatureLength);
            return signature.verify(paddedSignature);
        } else if (isValidDERSequence(signatureBytes)) {
            // Handle potential DER-wrapped RSA signatures (for backward compatibility)
            byte[] extractedSignature = extractSignatureFromDER(signatureBytes);
            if (extractedSignature.length == expectedSignatureLength) {
                return signature.verify(extractedSignature);
            }
        }
        
        // Fallback: try direct verification for legacy compatibility
        try {
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            // Log the issue for debugging but don't fail immediately
            System.err.println("RSA signature verification failed with unexpected format. " +
                "Expected length: " + expectedSignatureLength + ", Actual length: " + signatureBytes.length +
                " (SD-JWT standard expects consistent RSA signature format)");
            return false;
        }
    }

    /**
     * Pad signature to expected length with leading zeros.
     * This ensures SD-JWT standard compliance for RSA signatures.
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

    /**
     * Check if the byte array starts with a valid DER SEQUENCE tag.
     * This is a basic check for DER-wrapped signatures.
     *
     * @param bytes Input byte array
     * @return true if it appears to be a DER SEQUENCE
     */
    private boolean isValidDERSequence(byte[] bytes) {
        if (bytes.length < 2) {
            return false;
        }
        // Check for SEQUENCE tag (0x30)
        return bytes[0] == 0x30;
    }

    /**
     * Extract signature bytes from a DER-wrapped structure.
     * This handles edge cases where RSA signatures might be DER-encoded.
     *
     * @param derBytes DER-encoded bytes
     * @return Extracted signature bytes
     */
    private byte[] extractSignatureFromDER(byte[] derBytes) {
        try {
            // Simple DER parsing for SEQUENCE { signature }
            if (derBytes.length < 4 || derBytes[0] != 0x30) {
                return derBytes; // Not a valid DER SEQUENCE
            }

            int sequenceLength = derBytes[1] & 0xFF;
            if (sequenceLength >= 0x80) {
                // Long form length - handle multi-byte length
                int lengthBytes = sequenceLength & 0x7F;
                if (derBytes.length < 2 + lengthBytes) {
                    return derBytes;
                }
                
                sequenceLength = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    sequenceLength = (sequenceLength << 8) | (derBytes[2 + i] & 0xFF);
                }
                
                // Extract content after length bytes
                int contentStart = 2 + lengthBytes;
                if (derBytes.length >= contentStart + sequenceLength) {
                    byte[] content = new byte[sequenceLength];
                    System.arraycopy(derBytes, contentStart, content, 0, sequenceLength);
                    return content;
                }
            } else {
                // Short form length
                if (derBytes.length >= 2 + sequenceLength) {
                    byte[] content = new byte[sequenceLength];
                    System.arraycopy(derBytes, 2, content, 0, sequenceLength);
                    return content;
                }
            }
        } catch (Exception e) {
            // If DER parsing fails, return original bytes
            System.err.println("DER parsing failed for RSA signature: " + e.getMessage());
        }
        
        return derBytes; // Return original if parsing fails
    }
}
