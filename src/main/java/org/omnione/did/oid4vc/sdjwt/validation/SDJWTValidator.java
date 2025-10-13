package org.omnione.did.oid4vc.sdjwt.validation;

import org.omnione.did.oid4vc.sdjwt.core.Disclosure;
import org.omnione.did.oid4vc.sdjwt.core.SDJWT;
import org.omnione.did.oid4vc.core.util.Base64UrlUtils;
import org.omnione.did.oid4vc.core.util.HashUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

/**
 * SDJWTValidator provides comprehensive validation of SD-JWT structures
 * according to the SD-JWT specification.
 * 
 * This class validates the format, structure, and integrity of SD-JWTs
 * including verification of disclosure hashes and JWT format compliance.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDJWTValidator {
    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    /**
     * Result of SD-JWT validation containing validation status and details.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final List<String> errors;
        private final List<String> warnings;
        private final Map<String, Object> metadata;
        
        public ValidationResult(boolean valid, List<String> errors, List<String> warnings, Map<String, Object> metadata) {
            this.valid = valid;
            this.errors = new ArrayList<>(errors);
            this.warnings = new ArrayList<>(warnings);
            this.metadata = new LinkedHashMap<>(metadata);
        }
        
        public boolean isValid() { return valid; }
        public List<String> getErrors() { return Collections.unmodifiableList(errors); }
        public List<String> getWarnings() { return Collections.unmodifiableList(warnings); }
        public Map<String, Object> getMetadata() { return Collections.unmodifiableMap(metadata); }
        
        public boolean hasErrors() { return !errors.isEmpty(); }
        public boolean hasWarnings() { return !warnings.isEmpty(); }
    }
    
    /**
     * Validate a complete SD-JWT structure.
     * 
     * @param sdjwt the SD-JWT to validate
     * @return validation result
     */
    public ValidationResult validate(SDJWT sdjwt) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, Object> metadata = new LinkedHashMap<>();
        
        if (sdjwt == null) {
            errors.add("SD-JWT cannot be null");
            return new ValidationResult(false, errors, warnings, metadata);
        }
        
        // Validate credential JWT format
        validateCredentialJWT(sdjwt.getCredentialJwt(), errors, warnings, metadata);
        
        // Validate disclosures
        validateDisclosures(sdjwt.getDisclosures(), errors, warnings, metadata);
        
        // Validate key binding JWT if present
        if (sdjwt.hasKeyBindingJwt()) {
            validateKeyBindingJWT(sdjwt.getKeyBindingJwt(), errors, warnings, metadata);
        }
        
        // Cross-validate disclosures against credential JWT
        crossValidateDisclosures(sdjwt, errors, warnings, metadata);
        
        // Set metadata
        metadata.put("credentialJwtPresent", true);
        metadata.put("disclosureCount", sdjwt.getDisclosureCount());
        metadata.put("keyBindingJwtPresent", sdjwt.hasKeyBindingJwt());
        
        boolean valid = errors.isEmpty();
        return new ValidationResult(valid, errors, warnings, metadata);
    }
    
    /**
     * Validate an SD-JWT string without parsing.
     * 
     * @param sdJwtString the SD-JWT string to validate
     * @return validation result
     */
    public ValidationResult validateString(String sdJwtString) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, Object> metadata = new LinkedHashMap<>();
        
        if (sdJwtString == null || sdJwtString.trim().isEmpty()) {
            errors.add("SD-JWT string cannot be null or empty");
            return new ValidationResult(false, errors, warnings, metadata);
        }
        
        try {
            SDJWT sdjwt = SDJWT.parse(sdJwtString);
            return validate(sdjwt);
        } catch (Exception e) {
            errors.add("Failed to parse SD-JWT string: " + e.getMessage());
            return new ValidationResult(false, errors, warnings, metadata);
        }
    }
    
    /**
     * Validate a single disclosure.
     * 
     * @param disclosure the disclosure to validate
     * @return validation result
     */
    public ValidationResult validateDisclosure(Disclosure disclosure) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, Object> metadata = new LinkedHashMap<>();
        
        if (disclosure == null) {
            errors.add("Disclosure cannot be null");
            return new ValidationResult(false, errors, warnings, metadata);
        }
        
        // Validate salt
        if (disclosure.getSalt() == null || disclosure.getSalt().trim().isEmpty()) {
            errors.add("Disclosure salt cannot be null or empty");
        } else {
            if (!Base64UrlUtils.isValid(disclosure.getSalt())) {
                errors.add("Disclosure salt is not valid base64url");
            }
        }
        
        // Validate claim structure
        if (!disclosure.isArrayElement()) {
            if (disclosure.getClaimName() == null || disclosure.getClaimName().trim().isEmpty()) {
                errors.add("Object property disclosure must have a claim name");
            }
        }
        
        // Test disclosure string generation
        try {
            String disclosureString = disclosure.getDisclosure();
            metadata.put("disclosureString", disclosureString);
            metadata.put("disclosureLength", disclosureString.length());
        } catch (Exception e) {
            errors.add("Failed to generate disclosure string: " + e.getMessage());
        }
        
        // Test digest generation
        try {
            String digest = disclosure.digest();
            metadata.put("digest", digest);
        } catch (Exception e) {
            errors.add("Failed to generate disclosure digest: " + e.getMessage());
        }
        
        metadata.put("isArrayElement", disclosure.isArrayElement());
        metadata.put("claimName", disclosure.getClaimName());
        metadata.put("saltLength", disclosure.getSalt() != null ? disclosure.getSalt().length() : 0);
        
        boolean valid = errors.isEmpty();
        return new ValidationResult(valid, errors, warnings, metadata);
    }
    
    /**
     * Validate credential JWT format and structure.
     */
    private void validateCredentialJWT(String credentialJwt, List<String> errors, List<String> warnings, Map<String, Object> metadata) {
        if (credentialJwt == null || credentialJwt.trim().isEmpty()) {
            errors.add("Credential JWT cannot be null or empty");
            return;
        }
        
        // Check JWT format (3 parts separated by dots)
        String[] parts = credentialJwt.split("\\.");
        if (parts.length != 3) {
            errors.add("Credential JWT must have exactly 3 parts (header.payload.signature)");
            return;
        }
        
        // Validate header
        try {
            String headerJson = Base64UrlUtils.decodeToString(parts[0]);
            JsonNode header = OBJECT_MAPPER.readTree(headerJson);
            
            if (!header.has("alg")) {
                errors.add("Credential JWT header missing 'alg' claim");
            }
            
            if (header.has("typ")) {
                String typ = header.get("alg").asText();
                if (!"vc+sd-jwt".equals(typ) && !"JWT".equals(typ)) {
                    warnings.add("Credential JWT type is not 'vc+sd-jwt' or 'JWT': " + typ);
                }
            }
            
            metadata.put("credentialJwtAlgorithm", header.has("alg") ? header.get("alg").asText() : null);
            metadata.put("credentialJwtType", header.has("typ") ? header.get("typ").asText() : null);
            
        } catch (Exception e) {
            errors.add("Failed to parse credential JWT header: " + e.getMessage());
            return;
        }
        
        // Validate payload
        try {
            String payloadJson = Base64UrlUtils.decodeToString(parts[1]);
            JsonNode payload = OBJECT_MAPPER.readTree(payloadJson);
            
            // Check for required SD-JWT claims
            if (payload.has("_sd_alg")) {
                String sdAlg = payload.get("_sd_alg").asText();
                if (!HashUtils.isSupportedHashAlgorithm(sdAlg)) {
                    errors.add("Unsupported _sd_alg: " + sdAlg);
                }
                metadata.put("sdHashAlgorithm", sdAlg);
            } else {
                warnings.add("Credential JWT payload missing '_sd_alg' claim");
            }
            
            if (payload.has("_sd")) {
                JsonNode sdArray = payload.get("_sd");
                if (!sdArray.isArray()) {
                    errors.add("_sd claim must be an array");
                } else {
                    metadata.put("sdArraySize", sdArray.size());
                }
            }
            
            // Check for standard JWT claims
            metadata.put("hasIssuer", payload.has("iss"));
            metadata.put("hasSubject", payload.has("sub"));
            metadata.put("hasAudience", payload.has("aud"));
            metadata.put("hasExpiration", payload.has("exp"));
            metadata.put("hasIssuedAt", payload.has("iat"));
            
        } catch (Exception e) {
            errors.add("Failed to parse credential JWT payload: " + e.getMessage());
        }
    }
    
    /**
     * Validate all disclosures in the SD-JWT.
     */
    private void validateDisclosures(List<Disclosure> disclosures, List<String> errors, List<String> warnings, Map<String, Object> metadata) {
        if (disclosures == null) {
            warnings.add("Disclosures list is null");
            return;
        }
        
        int validDisclosures = 0;
        int arrayElementDisclosures = 0;
        int objectPropertyDisclosures = 0;
        Set<String> claimNames = new HashSet<>();
        
        for (int i = 0; i < disclosures.size(); i++) {
            Disclosure disclosure = disclosures.get(i);
            ValidationResult result = validateDisclosure(disclosure);
            
            if (result.isValid()) {
                validDisclosures++;
                
                if (disclosure.isArrayElement()) {
                    arrayElementDisclosures++;
                } else {
                    objectPropertyDisclosures++;
                    String claimName = disclosure.getClaimName();
                    if (claimNames.contains(claimName)) {
                        warnings.add("Duplicate claim name in disclosures: " + claimName);
                    }
                    claimNames.add(claimName);
                }
            } else {
                for (String error : result.getErrors()) {
                    errors.add("Disclosure " + i + ": " + error);
                }
            }
        }
        
        metadata.put("validDisclosures", validDisclosures);
        metadata.put("arrayElementDisclosures", arrayElementDisclosures);
        metadata.put("objectPropertyDisclosures", objectPropertyDisclosures);
        metadata.put("uniqueClaimNames", claimNames.size());
    }
    
    /**
     * Validate key binding JWT format and structure.
     */
    private void validateKeyBindingJWT(String keyBindingJwt, List<String> errors, List<String> warnings, Map<String, Object> metadata) {
        if (keyBindingJwt == null || keyBindingJwt.trim().isEmpty()) {
            warnings.add("Key binding JWT is empty");
            return;
        }
        
        // Check JWT format
        String[] parts = keyBindingJwt.split("\\.");
        if (parts.length != 3) {
            errors.add("Key binding JWT must have exactly 3 parts");
            return;
        }
        
        try {
            // Validate header
            String headerJson = Base64UrlUtils.decodeToString(parts[0]);
            JsonNode header = OBJECT_MAPPER.readTree(headerJson);
            
            if (!header.has("alg")) {
                errors.add("Key binding JWT header missing 'alg' claim");
            }
            
            if (header.has("typ")) {
                String typ = header.get("typ").asText();
                if (!"kb+jwt".equals(typ) && !"JWT".equals(typ)) {
                    warnings.add("Key binding JWT type is not 'kb+jwt' or 'JWT': " + typ);
                }
            }
            
            // Validate payload
            String payloadJson = Base64UrlUtils.decodeToString(parts[1]);
            JsonNode payload = OBJECT_MAPPER.readTree(payloadJson);
            
            metadata.put("keyBindingJwtAlgorithm", header.has("alg") ? header.get("alg").asText() : null);
            metadata.put("keyBindingJwtHasAudience", payload.has("aud"));
            metadata.put("keyBindingJwtHasNonce", payload.has("nonce"));
            metadata.put("keyBindingJwtHasIssuedAt", payload.has("iat"));
            
        } catch (Exception e) {
            errors.add("Failed to parse key binding JWT: " + e.getMessage());
        }
    }
    
    /**
     * Cross-validate disclosures against the credential JWT payload.
     */
    private void crossValidateDisclosures(SDJWT sdjwt, List<String> errors, List<String> warnings, Map<String, Object> metadata) {
        try {
            // Parse credential JWT payload
            String[] jwtParts = sdjwt.getCredentialJwt().split("\\.");
            String payloadJson = Base64UrlUtils.decodeToString(jwtParts[1]);
            JsonNode payload = OBJECT_MAPPER.readTree(payloadJson);
            
            if (!payload.has("_sd")) {
                if (!sdjwt.getDisclosures().isEmpty()) {
                    warnings.add("SD-JWT has disclosures but credential JWT has no _sd array");
                }
                return;
            }
            
            JsonNode sdArray = payload.get("_sd");
            if (!sdArray.isArray()) {
                return;
            }
            
            // Get hash algorithm
            String hashAlgorithm = HashUtils.getDefaultHashAlgorithm();
            if (payload.has("_sd_alg")) {
                hashAlgorithm = payload.get("_sd_alg").asText();
            }
            
            // Collect disclosure digests
            Set<String> disclosureDigests = new HashSet<>();
            for (Disclosure disclosure : sdjwt.getDisclosures()) {
                if (!disclosure.isArrayElement()) { // Only object property disclosures
                    disclosureDigests.add(disclosure.digest(hashAlgorithm));
                }
            }
            
            // Check if all _sd array entries have corresponding disclosures
            Set<String> sdArrayDigests = new HashSet<>();
            for (JsonNode digestNode : sdArray) {
                if (digestNode.isTextual()) {
                    String digest = digestNode.asText();
                    sdArrayDigests.add(digest);
                    
                    if (!disclosureDigests.contains(digest)) {
                        warnings.add("_sd array contains digest not found in disclosures: " + digest);
                    }
                }
            }
            
            // Check for disclosures not referenced in _sd array
            for (String disclosureDigest : disclosureDigests) {
                if (!sdArrayDigests.contains(disclosureDigest)) {
                    warnings.add("Disclosure digest not found in _sd array: " + disclosureDigest);
                }
            }
            
            metadata.put("sdArrayDigests", sdArrayDigests.size());
            metadata.put("disclosureDigests", disclosureDigests.size());
            metadata.put("digestsMatch", sdArrayDigests.equals(disclosureDigests));
            
        } catch (Exception e) {
            warnings.add("Failed to cross-validate disclosures: " + e.getMessage());
        }
    }
}