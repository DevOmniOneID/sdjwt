package org.omnione.did.oid4vc.sdjwt.codec;

import org.omnione.did.oid4vc.sdjwt.core.Disclosure;
import org.omnione.did.oid4vc.core.util.HashUtils;

import java.util.*;

/**
 * SDObjectDecoder is a utility to decode selectively-disclosable elements
 * in a map or a list recursively.
 * 
 * The decoder reconstructs the original data structure by replacing digest
 * values with actual claim values from the provided disclosures.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class SDObjectDecoder {
    
    private final String defaultHashAlgorithm;
    private final Map<String, Disclosure> digestToDisclosureMap;
    
    /**
     * Create an SDObjectDecoder with default hash algorithm (SHA-256).
     */
    public SDObjectDecoder() {
        this(HashUtils.getDefaultHashAlgorithm());
    }
    
    /**
     * Create an SDObjectDecoder with specified default hash algorithm.
     * 
     * @param defaultHashAlgorithm the default hash algorithm to use
     */
    public SDObjectDecoder(String defaultHashAlgorithm) {
        if (!HashUtils.isSupportedHashAlgorithm(defaultHashAlgorithm)) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + defaultHashAlgorithm);
        }
        
        this.defaultHashAlgorithm = defaultHashAlgorithm;
        this.digestToDisclosureMap = new HashMap<>();
    }
    
    /**
     * Decode an encoded map using the provided disclosures.
     * If all disclosures are provided, the original dataset should be restored.
     * If only a subset is provided, only corresponding claims are restored.
     * 
     * @param encodedMap the encoded map containing "_sd" arrays
     * @param disclosures the disclosures to use for decoding
     * @return the decoded map
     * @throws IllegalArgumentException if encodedMap is null
     */
    public Map<String, Object> decode(Map<String, Object> encodedMap, List<Disclosure> disclosures) {
        if (encodedMap == null) {
            throw new IllegalArgumentException("Encoded map cannot be null");
        }
        
        if (disclosures == null) {
            disclosures = Collections.emptyList();
        }
        
        // Build digest lookup map
        buildDigestMap(disclosures, encodedMap);
        
        return decodeMapRecursive(encodedMap);
    }
    
    /**
     * Decode an encoded list using the provided disclosures.
     * 
     * @param encodedList the encoded list containing selective disclosure elements
     * @param disclosures the disclosures to use for decoding
     * @return the decoded list
     * @throws IllegalArgumentException if encodedList is null
     */
    public List<Object> decode(List<Object> encodedList, List<Disclosure> disclosures) {
        if (encodedList == null) {
            throw new IllegalArgumentException("Encoded list cannot be null");
        }
        
        if (disclosures == null) {
            disclosures = Collections.emptyList();
        }
        
        // Build digest lookup map (use default hash algorithm for lists)
        Map<String, Object> dummyMap = Map.of("_sd_alg", defaultHashAlgorithm);
        buildDigestMap(disclosures, dummyMap);
        
        return decodeListRecursive(encodedList);
    }
    
    /**
     * Build a map from digest values to disclosures for efficient lookup.
     */
    private void buildDigestMap(List<Disclosure> disclosures, Map<String, Object> encodedMap) {
        digestToDisclosureMap.clear();
        
        // Determine hash algorithm from the encoded map or use default
        String hashAlgorithm = defaultHashAlgorithm;
        if (encodedMap.containsKey("_sd_alg")) {
            Object sdAlg = encodedMap.get("_sd_alg");
            if (sdAlg instanceof String) {
                hashAlgorithm = (String) sdAlg;
            }
        }
        
        // Build digest map
        for (Disclosure disclosure : disclosures) {
            String digest = disclosure.digest(hashAlgorithm);
            digestToDisclosureMap.put(digest, disclosure);
        }
    }
    
    /**
     * Recursively decode a map.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> decodeMapRecursive(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return new LinkedHashMap<>(map != null ? map : Collections.emptyMap());
        }
        
        Map<String, Object> result = new LinkedHashMap<>();
        
        // Process regular claims first
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            // Skip _sd and _sd_alg as they are metadata
            if ("_sd".equals(key) || "_sd_alg".equals(key)) {
                continue;
            }
            
            // Recursively process nested structures
            Object decodedValue = decodeValueRecursive(value);
            result.put(key, decodedValue);
        }
        
        // Process _sd array to restore selectively disclosed claims
        if (map.containsKey("_sd")) {
            Object sdValue = map.get("_sd");
            if (sdValue instanceof List) {
                List<?> sdArray = (List<?>) sdValue;
                for (Object digestObj : sdArray) {
                    if (digestObj instanceof String) {
                        String digest = (String) digestObj;
                        Disclosure disclosure = digestToDisclosureMap.get(digest);
                        if (disclosure != null && !disclosure.isArrayElement()) {
                            // Restore the claim
                            String claimName = disclosure.getClaimName();
                            Object claimValue = decodeValueRecursive(disclosure.getClaimValue());
                            result.put(claimName, claimValue);
                        }
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Recursively decode a list.
     */
    @SuppressWarnings("unchecked")
    private List<Object> decodeListRecursive(List<Object> list) {
        if (list == null || list.isEmpty()) {
            return new ArrayList<>(list != null ? list : Collections.emptyList());
        }
        
        List<Object> result = new ArrayList<>();
        
        for (Object item : list) {
            if (isSelectiveDisclosureElement(item)) {
                // This is a selective disclosure element: {"...": "digest"}
                Map<String, Object> sdElement = (Map<String, Object>) item;
                String digest = (String) sdElement.get("...");
                
                Disclosure disclosure = digestToDisclosureMap.get(digest);
                if (disclosure != null && disclosure.isArrayElement()) {
                    // Restore the array element
                    Object claimValue = decodeValueRecursive(disclosure.getClaimValue());
                    result.add(claimValue);
                } else {
                    // Keep the selective disclosure element (not disclosed)
                    result.add(item);
                }
            } else {
                // Regular element, process recursively
                Object decodedItem = decodeValueRecursive(item);
                result.add(decodedItem);
            }
        }
        
        return result;
    }
    
    /**
     * Recursively decode a value, handling nested maps and lists.
     */
    @SuppressWarnings("unchecked")
    private Object decodeValueRecursive(Object value) {
        if (value instanceof Map) {
            return decodeMapRecursive((Map<String, Object>) value);
        } else if (value instanceof List) {
            return decodeListRecursive((List<Object>) value);
        } else {
            return value;
        }
    }
    
    /**
     * Check if an object is a selective disclosure element.
     * A selective disclosure element is a map with a single key "..." and a string value.
     */
    private boolean isSelectiveDisclosureElement(Object obj) {
        if (!(obj instanceof Map)) {
            return false;
        }
        
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) obj;
        
        return map.size() == 1 && 
               map.containsKey("...") && 
               map.get("...") instanceof String;
    }
    
    /**
     * Get information about the decoding process.
     * 
     * @return map containing decoding statistics
     */
    public Map<String, Object> getDecodingInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("availableDisclosures", digestToDisclosureMap.size());
        info.put("defaultHashAlgorithm", defaultHashAlgorithm);
        
        // Count disclosures by type
        long objectDisclosures = digestToDisclosureMap.values().stream()
                .filter(d -> !d.isArrayElement())
                .count();
        long arrayDisclosures = digestToDisclosureMap.values().stream()
                .filter(Disclosure::isArrayElement)
                .count();
        
        info.put("objectPropertyDisclosures", objectDisclosures);
        info.put("arrayElementDisclosures", arrayDisclosures);
        
        return info;
    }
    
    /**
     * Check if a specific claim can be disclosed with the available disclosures.
     * 
     * @param claimName the claim name to check
     * @param hashAlgorithm the hash algorithm to use
     * @return true if the claim can be disclosed
     */
    public boolean canDisclose(String claimName, String hashAlgorithm) {
        return digestToDisclosureMap.values().stream()
                .anyMatch(d -> claimName.equals(d.getClaimName()));
    }
    
    /**
     * Get the list of claim names that can be disclosed.
     * 
     * @return set of disclosable claim names
     */
    public Set<String> getDisclosableClaimNames() {
        Set<String> claimNames = new HashSet<>();
        for (Disclosure disclosure : digestToDisclosureMap.values()) {
            if (!disclosure.isArrayElement()) {
                claimNames.add(disclosure.getClaimName());
            }
        }
        return claimNames;
    }
    
    /**
     * Create a selective disclosure by including only specific claims.
     * 
     * @param encodedMap the encoded map
     * @param allDisclosures all available disclosures
     * @param claimNamesToDisclose the claim names to include in the result
     * @return decoded map containing only the specified claims
     */
    public Map<String, Object> selectivelyDisclose(Map<String, Object> encodedMap, 
                                                  List<Disclosure> allDisclosures, 
                                                  Set<String> claimNamesToDisclose) {
        if (claimNamesToDisclose == null || claimNamesToDisclose.isEmpty()) {
            return decodeMapRecursive(encodedMap);
        }
        
        // Filter disclosures to only include requested claims
        List<Disclosure> filteredDisclosures = allDisclosures.stream()
                .filter(d -> d.isArrayElement() || claimNamesToDisclose.contains(d.getClaimName()))
                .collect(ArrayList::new, (list, item) -> list.add(item), ArrayList::addAll);
        
        return decode(encodedMap, filteredDisclosures);
    }
    
    /**
     * Get the default hash algorithm being used.
     * 
     * @return the default hash algorithm
     */
    public String getDefaultHashAlgorithm() {
        return defaultHashAlgorithm;
    }
    
    @Override
    public String toString() {
        return String.format("SDObjectDecoder{defaultHashAlgorithm='%s', availableDisclosures=%d}", 
                defaultHashAlgorithm, digestToDisclosureMap.size());
    }
}