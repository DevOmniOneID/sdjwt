package com.example.oid4vc.sdjwt.jwt.crypto;

import com.example.oid4vc.sdjwt.jwt.JWSSigner;
import org.omnione.did.wallet.key.WalletManagerInterface;
import org.omnione.did.wallet.exception.WalletException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class ECDSASigner implements JWSSigner {

    private final ECPrivateKey privateKey;
    private final WalletManagerInterface walletManager;
    private final String keyId;

    /**
     * Create ECDSASigner with ECPrivateKey (existing constructor).
     */
    public ECDSASigner(ECPrivateKey privateKey) {
        this.privateKey = privateKey;
        this.walletManager = null;
        this.keyId = null;
    }

    /**
     * Create ECDSASigner with WalletManagerInterface.
     */
    public ECDSASigner(WalletManagerInterface walletManager, String keyId) {
        if (walletManager == null) {
            throw new IllegalArgumentException("Wallet manager cannot be null");
        }
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        this.privateKey = null;
        this.walletManager = walletManager;
        this.keyId = keyId;
    }

    @Override
    public byte[] sign(String signingInput) throws Exception {
        if (walletManager != null) {
            // Use WalletManager for signing
            return signWithWalletManager(signingInput);
        } else {
            // Use PrivateKey for signing (existing logic)
            return signWithPrivateKey(signingInput);
        }
    }

    /**
     * Sign using WalletManager.
     */
    private byte[] signWithWalletManager(String signingInput) throws Exception {
        try {
            // Hash the signing input with SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedInput = digest.digest(signingInput.getBytes(StandardCharsets.UTF_8));

            // Sign using wallet manager - it returns DER format signature
            byte[] signature = walletManager.generateCompactSignatureFromHash(keyId, hashedInput);
            
            // Debug: Print signature information
            System.out.println("=== WalletManager Signature Debug ===");
            System.out.println("Signature length: " + signature.length);
            System.out.println("First 10 bytes: " + java.util.Arrays.toString(java.util.Arrays.copyOf(signature, Math.min(10, signature.length))));
            if (signature.length > 0) {
                System.out.println("First byte (hex): 0x" + String.format("%02x", signature[0]));
            }
            
            // Check if it's already IEEE P1363 format (64 bytes)
            if (signature.length == 64) {
                System.out.println("Already in IEEE P1363 format (64 bytes)");
                return signature;
            } 
            // Check if it's 65 bytes with 0x20 prefix (modified P1363 format)
            else if (signature.length == 65 && signature[0] == 0x20) {
                System.out.println("Detected 65-byte signature with 0x20 prefix - extracting 64-byte P1363");
                byte[] p1363Signature = new byte[64];
                System.arraycopy(signature, 1, p1363Signature, 0, 64); // Skip first byte
                return p1363Signature;
            }
            // Check if it's DER format (starts with 0x30)
            else if (signature.length > 6 && signature[0] == 0x30) {
                System.out.println("Converting from DER format to IEEE P1363");
                return convertDERToP1363(signature);
            }
            // Unknown format
            else {
                System.out.println("Unknown signature format - trying as-is");
                throw new Exception("Unsupported signature format. Length: " + signature.length + 
                                  ", First byte: 0x" + String.format("%02x", signature[0]));
            }
            
        } catch (WalletException e) {
            throw new Exception("Failed to sign with wallet manager", e);
        }
    }

    /**
     * Sign using ECPrivateKey (existing logic).
     */
    private byte[] signWithPrivateKey(String signingInput) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signingInput.getBytes());
        
        byte[] signatureBytes = signature.sign();
        
        // Ensure IEEE P1363 format for SD-JWT standard compliance
        // SD-JWT specification requires IEEE P1363 format (r||s, 64 bytes for P-256)
        if (signatureBytes.length == 64) {
            // Already in IEEE P1363 format
            return signatureBytes;
        } else {
            // Convert DER to IEEE P1363 format
            return convertDERToP1363(signatureBytes);
        }
    }

    /**
     * Convert DER encoded ECDSA signature to IEEE P1363 format.
     * DER: ASN.1 SEQUENCE { INTEGER r, INTEGER s }
     * IEEE P1363: r||s (64 bytes total for P-256, 32 bytes each)
     *
     * @param derSignature DER encoded signature
     * @return IEEE P1363 format signature (64 bytes)
     * @throws IllegalArgumentException if DER parsing fails
     */
    private byte[] convertDERToP1363(byte[] derSignature) throws IllegalArgumentException {
        try {
            // Parse DER SEQUENCE
            if (derSignature.length < 6 || derSignature[0] != 0x30) {
                throw new IllegalArgumentException("Invalid DER signature format");
            }

            int sequenceLength = derSignature[1] & 0xFF;
            int offset = 2;

            // Handle long form length encoding if needed
            if ((sequenceLength & 0x80) != 0) {
                int lengthBytes = sequenceLength & 0x7F;
                if (lengthBytes > 4 || offset + lengthBytes >= derSignature.length) {
                    throw new IllegalArgumentException("Invalid DER length encoding");
                }
                
                sequenceLength = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    sequenceLength = (sequenceLength << 8) | (derSignature[offset++] & 0xFF);
                }
            }

            // Parse INTEGER r
            if (offset >= derSignature.length || derSignature[offset] != 0x02) {
                throw new IllegalArgumentException("Expected INTEGER tag for r");
            }
            offset++;

            int rLength = derSignature[offset++] & 0xFF;
            if (offset + rLength > derSignature.length) {
                throw new IllegalArgumentException("Invalid r length");
            }

            byte[] rBytes = new byte[rLength];
            System.arraycopy(derSignature, offset, rBytes, 0, rLength);
            offset += rLength;

            // Parse INTEGER s
            if (offset >= derSignature.length || derSignature[offset] != 0x02) {
                throw new IllegalArgumentException("Expected INTEGER tag for s");
            }
            offset++;

            int sLength = derSignature[offset++] & 0xFF;
            if (offset + sLength > derSignature.length) {
                throw new IllegalArgumentException("Invalid s length");
            }

            byte[] sBytes = new byte[sLength];
            System.arraycopy(derSignature, offset, sBytes, 0, sLength);

            // Convert to IEEE P1363 format (32 bytes each for P-256)
            byte[] r = toFixedLength(rBytes, 32);
            byte[] s = toFixedLength(sBytes, 32);

            // Combine r||s
            byte[] p1363Signature = new byte[64];
            System.arraycopy(r, 0, p1363Signature, 0, 32);
            System.arraycopy(s, 0, p1363Signature, 32, 32);

            return p1363Signature;

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to convert DER to P1363: " + e.getMessage(), e);
        }
    }

    /**
     * Convert a byte array to fixed length by padding with leading zeros or removing them.
     *
     * @param input Input byte array
     * @param targetLength Target length
     * @return Fixed length byte array
     */
    private byte[] toFixedLength(byte[] input, int targetLength) {
        if (input.length == targetLength) {
            return input;
        } else if (input.length > targetLength) {
            // Remove leading zeros (common in DER encoding)
            int leadingZeros = 0;
            for (int i = 0; i < input.length - targetLength; i++) {
                if (input[i] == 0) {
                    leadingZeros++;
                } else {
                    break;
                }
            }
            
            if (leadingZeros > 0 && input.length - leadingZeros == targetLength) {
                byte[] result = new byte[targetLength];
                System.arraycopy(input, leadingZeros, result, 0, targetLength);
                return result;
            } else {
                throw new IllegalArgumentException("Cannot convert to target length: " + targetLength);
            }
        } else {
            // Pad with leading zeros
            byte[] result = new byte[targetLength];
            System.arraycopy(input, 0, result, targetLength - input.length, input.length);
            return result;
        }
    }
}
