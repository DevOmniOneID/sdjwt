package org.omnione.did.oid4vc.sdjwt.validation;

import org.omnione.did.oid4vc.sdjwt.core.Disclosure;
import org.omnione.did.oid4vc.core.util.Base64UrlUtils;
import org.omnione.did.oid4vc.core.util.HashUtils;
import org.omnione.did.oid4vc.core.util.SaltGenerator;

import java.util.*;
import java.util.regex.Pattern;

/**
 * DisclosureValidator provides specialized validation for individual disclosures
 * and disclosure-related operations.
 *
 * This class focuses on validating disclosure format, content, and security
 * properties according to SD-JWT best practices.
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DisclosureValidator {

  // Patterns for claim name validation
  private static final Pattern VALID_CLAIM_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
  private static final Pattern RESERVED_CLAIM_NAME_PATTERN = Pattern.compile("^(_sd|_sd_alg|iss|sub|aud|exp|nbf|iat|jti)$");

  /**
   * Validation options for disclosure validation.
   */
  public static class ValidationOptions {
    private boolean strictClaimNameValidation = true;
    private boolean requireSecureSalt = true;
    private int minimumSaltEntropy = 128; // bits
    private boolean allowReservedClaimNames = false;
    private Set<String> additionalReservedNames = new HashSet<>();

    public boolean isStrictClaimNameValidation() { return strictClaimNameValidation; }
    public ValidationOptions setStrictClaimNameValidation(boolean strict) {
      this.strictClaimNameValidation = strict; return this;
    }

    public boolean isRequireSecureSalt() { return requireSecureSalt; }
    public ValidationOptions setRequireSecureSalt(boolean require) {
      this.requireSecureSalt = require; return this;
    }

    public int getMinimumSaltEntropy() { return minimumSaltEntropy; }
    public ValidationOptions setMinimumSaltEntropy(int bits) {
      this.minimumSaltEntropy = bits; return this;
    }

    public boolean isAllowReservedClaimNames() { return allowReservedClaimNames; }
    public ValidationOptions setAllowReservedClaimNames(boolean allow) {
      this.allowReservedClaimNames = allow; return this;
    }

    public Set<String> getAdditionalReservedNames() { return additionalReservedNames; }
    public ValidationOptions setAdditionalReservedNames(Set<String> names) {
      this.additionalReservedNames = new HashSet<>(names); return this;
    }

    public ValidationOptions addReservedName(String name) {
      this.additionalReservedNames.add(name); return this;
    }
  }

  /**
   * Detailed validation result for a disclosure.
   */
  public static class DisclosureValidationResult {
    private final boolean valid;
    private final List<String> errors;
    private final List<String> warnings;
    private final Map<String, Object> properties;

    public DisclosureValidationResult(boolean valid, List<String> errors, List<String> warnings, Map<String, Object> properties) {
      this.valid = valid;
      this.errors = new ArrayList<>(errors);
      this.warnings = new ArrayList<>(warnings);
      this.properties = new LinkedHashMap<>(properties);
    }

    public boolean isValid() { return valid; }
    public List<String> getErrors() { return Collections.unmodifiableList(errors); }
    public List<String> getWarnings() { return Collections.unmodifiableList(warnings); }
    public Map<String, Object> getProperties() { return Collections.unmodifiableMap(properties); }

    public boolean hasErrors() { return !errors.isEmpty(); }
    public boolean hasWarnings() { return !warnings.isEmpty(); }
  }

  private final ValidationOptions defaultOptions;

  /**
   * Create a disclosure validator with default options.
   */
  public DisclosureValidator() {
    this.defaultOptions = new ValidationOptions();
  }

  /**
   * Create a disclosure validator with custom default options.
   *
   * @param defaultOptions the default validation options
   */
  public DisclosureValidator(ValidationOptions defaultOptions) {
    this.defaultOptions = defaultOptions;
  }

  /**
   * Validate a disclosure with default options.
   *
   * @param disclosure the disclosure to validate
   * @return validation result
   */
  public DisclosureValidationResult validate(Disclosure disclosure) {
    return validate(disclosure, defaultOptions);
  }

  /**
   * Validate a disclosure with specific options.
   *
   * @param disclosure the disclosure to validate
   * @param options the validation options to use
   * @return validation result
   */
  public DisclosureValidationResult validate(Disclosure disclosure, ValidationOptions options) {
    List<String> errors = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    Map<String, Object> properties = new LinkedHashMap<>();

    if (disclosure == null) {
      errors.add("Disclosure cannot be null");
      return new DisclosureValidationResult(false, errors, warnings, properties);
    }

    // Validate salt
    validateSalt(disclosure.getSalt(), options, errors, warnings, properties);

    // Validate claim name (for object properties)
    if (!disclosure.isArrayElement()) {
      validateClaimName(disclosure.getClaimName(), options, errors, warnings, properties);
    }

    // Validate claim value
    validateClaimValue(disclosure.getClaimValue(), errors, warnings, properties);

    // Validate disclosure string generation
    validateDisclosureString(disclosure, errors, warnings, properties);

    // Validate digest generation
    validateDigestGeneration(disclosure, errors, warnings, properties);

    // Security analysis
    performSecurityAnalysis(disclosure, options, warnings, properties);

    boolean valid = errors.isEmpty();
    return new DisclosureValidationResult(valid, errors, warnings, properties);
  }

  /**
   * Validate a disclosure string without creating a Disclosure object.
   *
   * @param disclosureString the base64url-encoded disclosure string
   * @return validation result
   */
  public DisclosureValidationResult validateString(String disclosureString) {
    List<String> errors = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    Map<String, Object> properties = new LinkedHashMap<>();

    if (disclosureString == null || disclosureString.trim().isEmpty()) {
      errors.add("Disclosure string cannot be null or empty");
      return new DisclosureValidationResult(false, errors, warnings, properties);
    }

    properties.put("disclosureString", disclosureString);
    properties.put("stringLength", disclosureString.length());

    // Validate base64url format
    if (!Base64UrlUtils.isValid(disclosureString)) {
      errors.add("Disclosure string is not valid base64url");
      return new DisclosureValidationResult(false, errors, warnings, properties);
    }

    try {
      Disclosure disclosure = Disclosure.parse(disclosureString);
      return validate(disclosure);
    } catch (Exception e) {
      errors.add("Failed to parse disclosure string: " + e.getMessage());
      return new DisclosureValidationResult(false, errors, warnings, properties);
    }
  }

  /**
   * Validate multiple disclosures for consistency and uniqueness.
   *
   * @param disclosures the list of disclosures to validate
   * @return validation result
   */
  public DisclosureValidationResult validateMultiple(List<Disclosure> disclosures) {
    List<String> errors = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    Map<String, Object> properties = new LinkedHashMap<>();

    if (disclosures == null) {
      errors.add("Disclosures list cannot be null");
      return new DisclosureValidationResult(false, errors, warnings, properties);
    }

    properties.put("totalDisclosures", disclosures.size());

    Set<String> usedSalts = new HashSet<>();
    Set<String> usedClaimNames = new HashSet<>();
    Set<String> usedDigests = new HashSet<>();
    int validCount = 0;
    int arrayElementCount = 0;
    int objectPropertyCount = 0;

    for (int i = 0; i < disclosures.size(); i++) {
      Disclosure disclosure = disclosures.get(i);

      if (disclosure == null) {
        errors.add("Disclosure at index " + i + " is null");
        continue;
      }

      // Individual validation
      DisclosureValidationResult result = validate(disclosure);
      if (result.isValid()) {
        validCount++;
      } else {
        for (String error : result.getErrors()) {
          errors.add("Disclosure " + i + ": " + error);
        }
      }

      // Check for duplicates
      String salt = disclosure.getSalt();
      if (salt != null) {
        if (usedSalts.contains(salt)) {
          warnings.add("Duplicate salt found at index " + i + ": " + salt);
        }
        usedSalts.add(salt);
      }

      // Track claim names for object properties
      if (!disclosure.isArrayElement()) {
        objectPropertyCount++;
        String claimName = disclosure.getClaimName();
        if (claimName != null) {
          if (usedClaimNames.contains(claimName)) {
            warnings.add("Duplicate claim name found at index " + i + ": " + claimName);
          }
          usedClaimNames.add(claimName);
        }
      } else {
        arrayElementCount++;
      }

      // Check for digest collisions
      try {
        String digest = disclosure.digest();
        if (usedDigests.contains(digest)) {
          warnings.add("Digest collision found at index " + i + ": " + digest);
        }
        usedDigests.add(digest);
      } catch (Exception e) {
        // Individual validation will catch this
      }
    }

    properties.put("validDisclosures", validCount);
    properties.put("arrayElementDisclosures", arrayElementCount);
    properties.put("objectPropertyDisclosures", objectPropertyCount);
    properties.put("uniqueSalts", usedSalts.size());
    properties.put("uniqueClaimNames", usedClaimNames.size());
    properties.put("uniqueDigests", usedDigests.size());

    boolean valid = errors.isEmpty();
    return new DisclosureValidationResult(valid, errors, warnings, properties);
  }

  /**
   * Validate salt according to security requirements.
   */
  private void validateSalt(String salt, ValidationOptions options, List<String> errors, List<String> warnings, Map<String, Object> properties) {
    if (salt == null) {
      errors.add("Salt cannot be null");
      return;
    }

    if (salt.trim().isEmpty()) {
      errors.add("Salt cannot be empty");
      return;
    }

    properties.put("saltLength", salt.length());

    // Validate base64url format
    if (!Base64UrlUtils.isValid(salt)) {
      errors.add("Salt is not valid base64url");
      return;
    }

    if (options.isRequireSecureSalt()) {
      if (!SaltGenerator.isValid(salt)) {
        errors.add("Salt does not meet security requirements");
        return;
      }

      try {
        byte[] saltBytes = Base64UrlUtils.decode(salt);
        int entropyBits = saltBytes.length * 8;
        properties.put("saltEntropyBits", entropyBits);

        if (entropyBits < options.getMinimumSaltEntropy()) {
          warnings.add("Salt entropy (" + entropyBits + " bits) is below recommended minimum (" +
              options.getMinimumSaltEntropy() + " bits)");
        }
      } catch (Exception e) {
        errors.add("Failed to analyze salt entropy: " + e.getMessage());
      }
    }

    properties.put("saltValid", true);
  }

  /**
   * Validate claim name for object property disclosures.
   */
  private void validateClaimName(String claimName, ValidationOptions options, List<String> errors, List<String> warnings, Map<String, Object> properties) {
    if (claimName == null) {
      errors.add("Claim name cannot be null for object property disclosure");
      return;
    }

    if (claimName.trim().isEmpty()) {
      errors.add("Claim name cannot be empty for object property disclosure");
      return;
    }

    properties.put("claimName", claimName);
    properties.put("claimNameLength", claimName.length());

    if (options.isStrictClaimNameValidation()) {
      if (!VALID_CLAIM_NAME_PATTERN.matcher(claimName).matches()) {
        warnings.add("Claim name contains non-standard characters: " + claimName);
      }
    }

    // Check for reserved names
    if (!options.isAllowReservedClaimNames()) {
      if (RESERVED_CLAIM_NAME_PATTERN.matcher(claimName).matches()) {
        errors.add("Claim name is reserved: " + claimName);
      }

      if (options.getAdditionalReservedNames().contains(claimName)) {
        errors.add("Claim name is in additional reserved names: " + claimName);
      }
    }

    properties.put("claimNameValid", true);
  }

  /**
   * Validate claim value.
   */
  private void validateClaimValue(Object claimValue, List<String> errors, List<String> warnings, Map<String, Object> properties) {
    if (claimValue == null) {
      warnings.add("Claim value is null");
    }

    properties.put("claimValueType", claimValue != null ? claimValue.getClass().getSimpleName() : "null");

    // Check for potentially problematic values
    if (claimValue instanceof String) {
      String stringValue = (String) claimValue;
      if (stringValue.isEmpty()) {
        warnings.add("Claim value is empty string");
      }
      if (stringValue.length() > 10000) {
        warnings.add("Claim value is very long (" + stringValue.length() + " characters)");
      }
      properties.put("claimValueLength", stringValue.length());
    }

    if (claimValue instanceof Number) {
      Number numberValue = (Number) claimValue;
      properties.put("claimValueNumeric", numberValue);
    }

    if (claimValue instanceof Collection) {
      Collection<?> collectionValue = (Collection<?>) claimValue;
      properties.put("claimValueCollectionSize", collectionValue.size());
    }

    if (claimValue instanceof Map) {
      Map<?, ?> mapValue = (Map<?, ?>) claimValue;
      properties.put("claimValueMapSize", mapValue.size());
    }
  }

  /**
   * Validate disclosure string generation.
   */
  private void validateDisclosureString(Disclosure disclosure, List<String> errors, List<String> warnings, Map<String, Object> properties) {
    try {
      String disclosureString = disclosure.getDisclosure();
      properties.put("generatedDisclosureString", disclosureString);
      properties.put("disclosureStringLength", disclosureString.length());

      // Validate round-trip
      Disclosure parsed = Disclosure.parse(disclosureString);
      if (!disclosure.equals(parsed)) {
        errors.add("Disclosure round-trip validation failed");
      } else {
        properties.put("roundTripValid", true);
      }

    } catch (Exception e) {
      errors.add("Failed to generate disclosure string: " + e.getMessage());
    }
  }

  /**
   * Validate digest generation with multiple algorithms.
   */
  private void validateDigestGeneration(Disclosure disclosure, List<String> errors, List<String> warnings, Map<String, Object> properties) {
    Map<String, String> digests = new LinkedHashMap<>();

    for (String algorithm : HashUtils.getSupportedAlgorithms()) {
      try {
        String digest = disclosure.digest(algorithm);
        digests.put(algorithm, digest);

        // Validate digest format
        if (!Base64UrlUtils.isValid(digest)) {
          errors.add("Generated digest for " + algorithm + " is not valid base64url");
        }

      } catch (Exception e) {
        warnings.add("Failed to generate digest for " + algorithm + ": " + e.getMessage());
      }
    }

    properties.put("generatedDigests", digests);
    properties.put("digestCount", digests.size());

    // Check digest uniqueness across algorithms
    Set<String> uniqueDigests = new HashSet<>(digests.values());
    if (uniqueDigests.size() != digests.size()) {
      warnings.add("Some digest algorithms produced identical results");
    }
  }

  /**
   * Perform security analysis of the disclosure.
   */
  private void performSecurityAnalysis(Disclosure disclosure, ValidationOptions options, List<String> warnings, Map<String, Object> properties) {
    // Analyze salt randomness (basic check)
    String salt = disclosure.getSalt();
    if (salt != null) {
      if (salt.contains("test") || salt.contains("demo") || salt.contains("example")) {
        warnings.add("Salt appears to contain test/demo data");
      }

      // Check for obviously weak salts
      if (salt.length() < 16) {
        warnings.add("Salt is shorter than recommended minimum");
      }
    }

    // Analyze claim value for sensitive information patterns
    Object claimValue = disclosure.getClaimValue();
    if (claimValue instanceof String) {
      String stringValue = (String) claimValue;

      // Basic patterns for potentially sensitive data
      if (stringValue.matches(".*\\b\\d{3}-\\d{2}-\\d{4}\\b.*")) {
        warnings.add("Claim value may contain SSN pattern");
      }
      if (stringValue.matches(".*\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b.*")) {
        warnings.add("Claim value may contain credit card pattern");
      }
      if (stringValue.toLowerCase().contains("password") || stringValue.toLowerCase().contains("secret")) {
        warnings.add("Claim value may contain sensitive keywords");
      }
    }

    properties.put("securityAnalysisPerformed", true);
  }

  /**
   * Create validation options for strict security requirements.
   *
   * @return validation options with strict security settings
   */
  public static ValidationOptions createStrictOptions() {
    return new ValidationOptions()
        .setStrictClaimNameValidation(true)
        .setRequireSecureSalt(true)
        .setMinimumSaltEntropy(128)
        .setAllowReservedClaimNames(false);
  }

  /**
   * Create validation options for lenient validation (e.g., for testing).
   *
   * @return validation options with lenient settings
   */
  public static ValidationOptions createLenientOptions() {
    return new ValidationOptions()
        .setStrictClaimNameValidation(false)
        .setRequireSecureSalt(false)
        .setMinimumSaltEntropy(64)
        .setAllowReservedClaimNames(true);
  }

  /**
   * Validate that a set of disclosures doesn't reveal information through correlation.
   *
   * @param disclosures the disclosures to analyze
   * @return validation result with correlation analysis
   */
  public DisclosureValidationResult validatePrivacyProperties(List<Disclosure> disclosures) {
    List<String> errors = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    Map<String, Object> properties = new LinkedHashMap<>();

    if (disclosures == null || disclosures.isEmpty()) {
      return new DisclosureValidationResult(true, errors, warnings, properties);
    }

    // Analyze salt patterns
    Map<String, Integer> saltPrefixes = new HashMap<>();
    for (Disclosure disclosure : disclosures) {
      String salt = disclosure.getSalt();
      if (salt != null && salt.length() >= 4) {
        String prefix = salt.substring(0, 4);
        saltPrefixes.put(prefix, saltPrefixes.getOrDefault(prefix, 0) + 1);
      }
    }

    // Check for suspicious salt patterns
    for (Map.Entry<String, Integer> entry : saltPrefixes.entrySet()) {
      if (entry.getValue() > 1) {
        warnings.add("Multiple salts share prefix '" + entry.getKey() + "' (" + entry.getValue() + " occurrences)");
      }
    }

    // Analyze claim name patterns
    Set<String> claimNames = new HashSet<>();
    for (Disclosure disclosure : disclosures) {
      if (!disclosure.isArrayElement()) {
        claimNames.add(disclosure.getClaimName());
      }
    }

    properties.put("uniqueClaimNames", claimNames.size());
    properties.put("totalDisclosures", disclosures.size());
    properties.put("saltPrefixAnalysis", saltPrefixes);

    boolean valid = errors.isEmpty();
    return new DisclosureValidationResult(valid, errors, warnings, properties);
  }

  /**
   * Get the default validation options.
   *
   * @return the default validation options
   */
  public ValidationOptions getDefaultOptions() {
    return defaultOptions;
  }
}