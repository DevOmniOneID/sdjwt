package org.omnione.did.oid4vc.dcql;

import org.omnione.did.oid4vc.dcql.dto.DCQLQuery;

import java.util.*;

/**
 * DCQL query validation utility
 * Validation compliant with OpenID4VP 1.0 Section 6 (DCQL) specification
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLQueryValidator {

  /**
   * Validate entire DCQL query validity
   *
   * @param dcqlQuery DCQL query to validate
   * @return validation result
   */
  public static ValidationResult validate(DCQLQuery dcqlQuery) {
    ValidationResult result = new ValidationResult();

    if (dcqlQuery == null) {
      result.addError("DCQL query is null");
      return result;
    }

    // 1. Validate basic structure
    validateBasicStructure(dcqlQuery, result);

    // 2. Validate Credentials
    if (dcqlQuery.getCredentials() != null) {
      validateCredentials(dcqlQuery.getCredentials(), result);
    }

    // 3. Validate Credential Sets
    if (dcqlQuery.getCredentialSets() != null) {
      validateCredentialSets(dcqlQuery.getCredentialSets(), dcqlQuery.getCredentials(), result);
    }

    // 4. Validate overall consistency
    validateConsistency(dcqlQuery, result);


    return result;
  }

  /**
   * Validate basic structure of DCQL query
   */
  private static void validateBasicStructure(DCQLQuery dcqlQuery, ValidationResult result) {
    // Either credentials or credential_sets must be present
    boolean hasCredentials = dcqlQuery.getCredentials() != null && !dcqlQuery.getCredentials().isEmpty();
    boolean hasCredentialSets = dcqlQuery.getCredentialSets() != null && !dcqlQuery.getCredentialSets().isEmpty();

    if (!hasCredentials && !hasCredentialSets) {
      result.addError("DCQL query must have either 'credentials' or 'credential_sets'");
    }

    if (hasCredentials && hasCredentialSets) {
      result.addWarning("DCQL query has both 'credentials' and 'credential_sets' - credential_sets takes precedence");
    }
  }

  /**
   * Validate Credentials array
   */
  private static void validateCredentials(List<DCQLQuery.CredentialQuery> credentials, ValidationResult result) {
    if (credentials.isEmpty()) {
      result.addError("'credentials' array cannot be empty");
      return;
    }

    Set<String> credentialIds = new HashSet<>();

    for (int i = 0; i < credentials.size(); i++) {
      DCQLQuery.CredentialQuery credential = credentials.get(i);
      String context = "credentials[" + i + "]";

      validateCredential(credential, context, result);

      // Check for duplicate IDs
      if (credential.getId() != null) {
        if (credentialIds.contains(credential.getId())) {
          result.addError("Duplicate credential ID: " + credential.getId());
        } else {
          credentialIds.add(credential.getId());
        }
      }
    }
  }

  /**
   * Validate individual Credential
   */
  private static void validateCredential(DCQLQuery.CredentialQuery credential, String context, ValidationResult result) {
    if (credential == null) {
      result.addError(context + " is null");
      return;
    }

    // Validate required fields
    validateRequiredField(credential.getId(), "id", context, result);
    validateRequiredField(credential.getFormat(), "format", context, result);

    // Validate ID format
    if (credential.getId() != null) {
      validateCredentialId(credential.getId(), context, result);
    }

    // Validate format
    if (credential.getFormat() != null) {
      validateFormat(credential.getFormat(), context, result);
    }

    // Validate Claims
    if (credential.getClaims() != null) {
      validateClaims(credential.getClaims(), context, result);
    }

    // Validate Claim Sets
    if (credential.getClaimSets() != null) {
      validateCredentialClaimSets(credential.getClaimSets(), context, result);

      // Warn if both claims and claim_sets exist
      if (credential.getClaims() != null) {
        result.addWarning(context + " has both 'claims' and 'claim_sets' - claim_sets takes precedence");
      }
    }

    // Validate Meta
    if (credential.getMeta() != null) {
      validateMeta(credential.getMeta(), context, result);
    }
  }

  /**
   * Validate Claims array
   */
  private static void validateClaims(List<DCQLQuery.ClaimQuery> claims, String context, ValidationResult result) {
    for (int i = 0; i < claims.size(); i++) {
      DCQLQuery.ClaimQuery claim = claims.get(i);
      String claimContext = context + ".claims[" + i + "]";

      if (claim == null) {
        result.addError(claimContext + " is null");
        continue;
      }

      // Path is required
      if (claim.getPath() == null || claim.getPath().isEmpty()) {
        result.addError(claimContext + ".path is required and cannot be empty");
      } else {
        validatePath(claim.getPath(), claimContext + ".path", result);
      }

      // Validate Values (optional)
      if (claim.getValues() != null) {
        validateValues(claim.getValues(), claimContext + ".values", result);
      }
    }
  }

  /**
   * Validate Path
   */
  private static void validatePath(List<Object> path, String context, ValidationResult result) {
    if (!DCQLPathProcessor.isValidPath(path)) {
      result.addError(context + " contains invalid elements");
    }

    for (int i = 0; i < path.size(); i++) {
      Object element = path.get(i);
      if (element == null) {
        // null means all elements of array and is allowed
        continue;
      } else if (element instanceof String) {
        String strElement = (String) element;
        if (strElement.trim().isEmpty()) {
          result.addError(context + "[" + i + "] cannot be empty string");
        }
      } else if (!(element instanceof Integer)) {
        result.addError(context + "[" + i + "] must be string, integer, or null");
      }
    }
  }

  /**
   * Validate Values array
   */
  private static void validateValues(List<Object> values, String context, ValidationResult result) {
    if (values.isEmpty()) {
      result.addWarning(context + " is empty - no value restrictions will be applied");
    }

    // Check type consistency of values
    Set<Class<?>> valueTypes = new HashSet<>();
    for (Object value : values) {
      if (value != null) {
        valueTypes.add(value.getClass());
      }
    }

    if (valueTypes.size() > 1) {
      result.addWarning(context + " contains mixed value types - may cause matching issues");
    }
  }

  /**
   * Validate Credential Sets
   */
  private static void validateCredentialSets(List<DCQLQuery.CredentialSet> credentialSets,
      List<DCQLQuery.CredentialQuery> credentials,
      ValidationResult result) {
    if (credentialSets.isEmpty()) {
      result.addError("'credential_sets' array cannot be empty");
      return;
    }

    Set<String> availableCredentialIds = new HashSet<>();
    if (credentials != null) {
      credentials.stream()
          .map(DCQLQuery.CredentialQuery::getId)
          .filter(Objects::nonNull)
          .forEach(availableCredentialIds::add);
    }

    for (int i = 0; i < credentialSets.size(); i++) {
      DCQLQuery.CredentialSet credentialSet = credentialSets.get(i);
      String context = "credential_sets[" + i + "]";

      validateCredentialSet(credentialSet, context, availableCredentialIds, result);
    }
  }

  /**
   * Validate individual Credential Set
   */
  private static void validateCredentialSet(DCQLQuery.CredentialSet credentialSet,
      String context,
      Set<String> availableCredentialIds,
      ValidationResult result) {
    if (credentialSet == null) {
      result.addError(context + " is null");
      return;
    }

    // Options are required
    if (credentialSet.getOptions() == null || credentialSet.getOptions().isEmpty()) {
      result.addError(context + ".options is required and cannot be empty");
      return;
    }

    // Validate each option
    for (int i = 0; i < credentialSet.getOptions().size(); i++) {
      List<String> option = credentialSet.getOptions().get(i);
      String optionContext = context + ".options[" + i + "]";

      if (option == null || option.isEmpty()) {
        result.addError(optionContext + " cannot be null or empty");
        continue;
      }

      // Check if credential IDs in options are actually defined
      for (String credentialId : option) {
        if (!availableCredentialIds.contains(credentialId)) {
          result.addError(optionContext + " references undefined credential ID: " + credentialId);
        }
      }
    }
  }

  /**
   * Validate overall consistency
   */
  private static void validateConsistency(DCQLQuery dcqlQuery, ValidationResult result) {
    // Credential ID uniqueness check is already done in validateCredentials

    // Additional consistency checks...
    // Example: check if claim IDs referenced in claim_sets are actually defined, etc.
  }

  // Helper methods
  private static void validateRequiredField(String value, String fieldName, String context, ValidationResult result) {
    if (value == null || value.trim().isEmpty()) {
      result.addError(context + "." + fieldName + " is required");
    }
  }

  private static void validateCredentialId(String id, String context, ValidationResult result) {
    // OpenID4VP Section 6.1 ID rule: only alphanumeric, underscore, hyphen are allowed
    if (!id.matches("^[a-zA-Z0-9_-]+$")) {
      result.addError(context + ".id must contain only alphanumeric characters, underscores, and hyphens");
    }
  }

  private static void validateFormat(String format, String context, ValidationResult result) {
    // List of supported formats
    Set<String> supportedFormats = Set.of(
        "dc+sd-jwt", "vc+sd-jwt", "sd-jwt",
        "jwt_vc_json", "jwt_vc", "ldp_vc"
    );

    if (!supportedFormats.contains(format)) {
      result.addWarning(context + ".format '" + format + "' may not be supported");
    }
  }

  private static void validateMeta(Map<String, Object> meta, String context, ValidationResult result) {
    // Metadata validation (currently only basic checks)
    if (meta.isEmpty()) {
      result.addWarning(context + ".meta is empty");
    }

    // Validate vct_values
    if (meta.containsKey("vct_values")) {
      Object vctValues = meta.get("vct_values");
      if (!(vctValues instanceof List)) {
        result.addError(context + ".meta.vct_values must be an array");
      }
    }
  }

  private static void validateCredentialClaimSets(List<DCQLQuery.ClaimSet> claimSets, String context, ValidationResult result) {
    // Validate Claim Sets logic (currently only basic checks)
    if (claimSets.isEmpty()) {
      result.addError(context + ".claim_sets cannot be empty");
    }

    for (int i = 0; i < claimSets.size(); i++) {
      DCQLQuery.ClaimSet claimSet = claimSets.get(i);
      if (claimSet == null) {
        result.addError(context + ".claim_sets[" + i + "] cannot be null");
        continue;
      }

      // Validate ClaimSet's claims
      if (claimSet.getClaims() == null || claimSet.getClaims().isEmpty()) {
        result.addError(context + ".claim_sets[" + i + "].claims cannot be null or empty");
      }
    }
  }

  /**
   * Class containing validation results
   */
  public static class ValidationResult {
    private final List<String> errors = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public void addError(String error) {
      errors.add(error);
    }

    public void addWarning(String warning) {
      warnings.add(warning);
    }

    public List<String> getErrors() { return Collections.unmodifiableList(errors); }
    public List<String> getWarnings() { return Collections.unmodifiableList(warnings); }

    public boolean isValid() { return errors.isEmpty(); }
    public boolean hasWarnings() { return !warnings.isEmpty(); }
    public boolean hasErrors() { return !errors.isEmpty(); }

    public String getSummary() {
      return String.format("Validation: %d errors, %d warnings", errors.size(), warnings.size());
    }
  }
}