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
        
        byte[] signatureBytes = signedJWT.getSignatureBytes();
        
        // Support both DER and IEEE P1363 signature formats for cross-platform compatibility
        if (signatureBytes.length == 64) {
            // IEEE P1363 format (r||s, each 32 bytes) - convert to DER for verification
            byte[] derSignature = convertP1363ToDER(signatureBytes);
            return signature.verify(derSignature);
        } else {
            // DER format - verify directly
            return signature.verify(signatureBytes);
        }
    }

    /**
     * Convert IEEE P1363 signature format to DER format.
     * IEEE P1363: r||s (64 bytes total, 32 bytes each)
     * DER: ASN.1 SEQUENCE { INTEGER r, INTEGER s }
     *
     * @param p1363Signature IEEE P1363 format signature (64 bytes)
     * @return DER encoded signature
     */
    private byte[] convertP1363ToDER(byte[] p1363Signature) {
        if (p1363Signature.length != 64) {
            throw new IllegalArgumentException("IEEE P1363 signature must be 64 bytes");
        }

        // Extract r and s (32 bytes each)
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(p1363Signature, 0, r, 0, 32);
        System.arraycopy(p1363Signature, 32, s, 0, 32);

        // Remove leading zeros from r and s, but keep at least one byte
        r = removeLeadingZeros(r);
        s = removeLeadingZeros(s);

        // Add leading zero if first bit is set (to ensure positive integer in ASN.1)
        if ((r[0] & 0x80) != 0) {
            byte[] temp = new byte[r.length + 1];
            temp[0] = 0;
            System.arraycopy(r, 0, temp, 1, r.length);
            r = temp;
        }
        if ((s[0] & 0x80) != 0) {
            byte[] temp = new byte[s.length + 1];
            temp[0] = 0;
            System.arraycopy(s, 0, temp, 1, s.length);
            s = temp;
        }

        // Build DER SEQUENCE
        // SEQUENCE { INTEGER r, INTEGER s }
        int rTotalLength = 2 + r.length; // tag + length + value
        int sTotalLength = 2 + s.length; // tag + length + value
        int sequenceContentLength = rTotalLength + sTotalLength;
        int totalLength = 2 + sequenceContentLength; // sequence tag + length + content

        byte[] derSignature = new byte[totalLength];
        int offset = 0;

        // SEQUENCE tag and length
        derSignature[offset++] = 0x30; // SEQUENCE tag
        derSignature[offset++] = (byte) sequenceContentLength;

        // INTEGER r
        derSignature[offset++] = 0x02; // INTEGER tag
        derSignature[offset++] = (byte) r.length;
        System.arraycopy(r, 0, derSignature, offset, r.length);
        offset += r.length;

        // INTEGER s
        derSignature[offset++] = 0x02; // INTEGER tag
        derSignature[offset++] = (byte) s.length;
        System.arraycopy(s, 0, derSignature, offset, s.length);

        return derSignature;
    }

    /**
     * Remove leading zero bytes from a byte array, but keep at least one byte.
     *
     * @param bytes Input byte array
     * @return Byte array with leading zeros removed
     */
    private byte[] removeLeadingZeros(byte[] bytes) {
        int leadingZeros = 0;
        for (int i = 0; i < bytes.length - 1; i++) { // Keep at least one byte
            if (bytes[i] == 0) {
                leadingZeros++;
            } else {
                break;
            }
        }

        if (leadingZeros == 0) {
            return bytes;
        }

        byte[] result = new byte[bytes.length - leadingZeros];
        System.arraycopy(bytes, leadingZeros, result, 0, result.length);
        return result;
    }
}
