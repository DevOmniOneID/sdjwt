package org.omnione.did.sdjwt.core;

import org.omnione.did.sdjwt.exception.SDJWTException;

import java.util.*;

/**
 * SDJWT represents an SD-JWT (Selective Disclosure JWT) which consists of:
 * - A credential JWT (issuer-signed JWT)
 * - Zero or more disclosures
 * - An optional key binding JWT
 *
 * The string representation follows the format:
 * <Credential-JWT>~<Disclosure-1>~...~<Disclosure-N>~[<Key-Binding-JWT>]
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWT {
    
    private final String credentialJwt;
    private final List<Disclosure> disclosures;
    private final String keyBindingJwt; // optional
    
    /**
     * Create an SDJWT without a key binding JWT.
     * 
     * @param credentialJwt the credential JWT (issuer-signed JWT)
     * @param disclosures the collection of disclosures
     * @throws IllegalArgumentException if credentialJwt is null or empty
     */
    public SDJWT(String credentialJwt, Collection<Disclosure> disclosures) {
        this(credentialJwt, disclosures, null);
    }
    
    /**
     * Create an SDJWT with an optional key binding JWT.
     * 
     * @param credentialJwt the credential JWT (issuer-signed JWT)
     * @param disclosures the collection of disclosures
     * @param keyBindingJwt the key binding JWT (optional, can be null)
     * @throws IllegalArgumentException if credentialJwt is null or empty
     */
    public SDJWT(String credentialJwt, Collection<Disclosure> disclosures, String keyBindingJwt) {
        if (credentialJwt == null || credentialJwt.trim().isEmpty()) {
            throw new IllegalArgumentException("Credential JWT cannot be null or empty");
        }
        
        this.credentialJwt = credentialJwt.trim();
        this.disclosures = disclosures != null ? 
            new ArrayList<>(disclosures) : new ArrayList<>();
        this.keyBindingJwt = keyBindingJwt != null && !keyBindingJwt.trim().isEmpty() ? 
            keyBindingJwt.trim() : null;
    }
    
    /**
     * Get the credential JWT.
     * 
     * @return the credential JWT
     */
    public String getCredentialJwt() {
        return credentialJwt;
    }
    
    /**
     * Get the list of disclosures.
     * 
     * @return an unmodifiable list of disclosures
     */
    public List<Disclosure> getDisclosures() {
        return Collections.unmodifiableList(disclosures);
    }
    
    /**
     * Get the key binding JWT.
     * 
     * @return the key binding JWT or null if not present
     */
    public String getKeyBindingJwt() {
        return keyBindingJwt;
    }
    
    /**
     * Check if this SD-JWT has a key binding JWT.
     * 
     * @return true if key binding JWT is present
     */
    public boolean hasKeyBindingJwt() {
        return keyBindingJwt != null;
    }
    
    /**
     * Get the number of disclosures.
     * 
     * @return the number of disclosures
     */
    public int getDisclosureCount() {
        return disclosures.size();
    }
    
    /**
     * Check if this SD-JWT has any disclosures.
     * 
     * @return true if there are disclosures
     */
    public boolean hasDisclosures() {
        return !disclosures.isEmpty();
    }
    

    
    /**
     * Parse an SD-JWT string into an SDJWT object.
     * 
     * @param sdJwtString the SD-JWT string to parse
     * @return the parsed SDJWT object
     * @throws SDJWTException if parsing fails
     */
    public static SDJWT parse(String sdJwtString) {
        if (sdJwtString == null || sdJwtString.trim().isEmpty()) {
            throw new SDJWTException("SD-JWT string cannot be null or empty");
        }
        
        // Split by tilde (~) while preserving empty strings
        String[] parts = sdJwtString.split("~", -1);
        
        if (parts.length < 1) {
            throw new SDJWTException("SD-JWT must contain at least a credential JWT");
        }
        
        // First part is always the credential JWT
        String credentialJwt = parts[0];
        if (credentialJwt.isEmpty()) {
            throw new SDJWTException("Credential JWT cannot be empty");
        }
        
        // Validate JWT format (should have 3 parts separated by dots)
        if (!isValidJwtFormat(credentialJwt)) {
            throw new SDJWTException("Invalid credential JWT format");
        }
        
        List<Disclosure> disclosures = new ArrayList<>();
        String keyBindingJwt = null;
        
        // Process remaining parts
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            
            if (part.isEmpty()) {
                // Empty part - could be between disclosures or before key binding JWT
                continue;
            }
            
            // Check if this part is a JWT (key binding JWT)
            if (isValidJwtFormat(part)) {
                // This should be the key binding JWT (last non-empty part)
                if (i == parts.length - 1 || areAllEmpty(parts, i + 1)) {
                    keyBindingJwt = part;
                } else {
                    throw new SDJWTException("Key binding JWT can only be the last component");
                }
            } else {
                // This should be a disclosure
                try {
                    Disclosure disclosure = Disclosure.parse(part);
                    disclosures.add(disclosure);
                } catch (Exception e) {
                    throw new SDJWTException("Failed to parse disclosure at position " + i + ": " + e.getMessage(), e);
                }
            }
        }
        
        return new SDJWT(credentialJwt, disclosures, keyBindingJwt);
    }
    
    /**
     * Check if all parts from the given index onward are empty.
     */
    private static boolean areAllEmpty(String[] parts, int fromIndex) {
        for (int i = fromIndex; i < parts.length; i++) {
            if (!parts[i].isEmpty()) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Validate JWT format (should have exactly 3 parts separated by dots).
     */
    private static boolean isValidJwtFormat(String jwt) {
        if (jwt == null || jwt.trim().isEmpty()) {
            return false;
        }
        
        String[] parts = jwt.split("\\.");
        return parts.length == 3 && 
               !parts[0].isEmpty() && 
               !parts[1].isEmpty(); // signature can be empty for unsigned JWTs
    }
    
    /**
     * Get the string representation of this SD-JWT.
     * Format: <Credential-JWT>~<Disclosure-1>~...~<Disclosure-N>~[<Key-Binding-JWT>]
     * 
     * @return the SD-JWT string
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        
        // Add credential JWT
        sb.append(credentialJwt);
        
        // Add disclosures
        for (Disclosure disclosure : disclosures) {
            sb.append("~").append(disclosure.getDisclosure());
        }
        
        // Add key binding JWT if present
        if (keyBindingJwt != null) {
            sb.append("~").append(keyBindingJwt);
        } else {
            // Add trailing tilde if no key binding JWT
            sb.append("~");
        }
        
        return sb.toString();
    }
    

    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SDJWT sdjwt = (SDJWT) o;
        return Objects.equals(credentialJwt, sdjwt.credentialJwt) &&
               Objects.equals(disclosures, sdjwt.disclosures) &&
               Objects.equals(keyBindingJwt, sdjwt.keyBindingJwt);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(credentialJwt, disclosures, keyBindingJwt);
    }
}