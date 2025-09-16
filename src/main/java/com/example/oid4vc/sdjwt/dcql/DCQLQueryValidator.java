package com.example.oid4vc.sdjwt.dcql;

import com.example.oid4vc.sdjwt.dto.DCQLQuery;

import java.util.*;

/**
 * DCQL 쿼리 유효성 검증 유틸리티
 * OpenID4VP 1.0 Section 6 (DCQL) 규격 준수 검증
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
public class DCQLQueryValidator {

  /**
   * DCQL 쿼리 전체 유효성 검증
   *
   * @param dcqlQuery 검증할 DCQL 쿼리
   * @return 검증 결과
   */
  public static ValidationResult validate(DCQLQuery dcqlQuery) {
    ValidationResult result = new ValidationResult();

    if (dcqlQuery == null) {
      result.addError("DCQL query is null");
      return result;
    }

    // 1. 기본 구조 검증
    validateBasicStructure(dcqlQuery, result);

    // 2. Credentials 검증
    if (dcqlQuery.getCredentials() != null) {
      validateCredentials(dcqlQuery.getCredentials(), result);
    }

    // 3. Credential Sets 검증
    if (dcqlQuery.getCredentialSets() != null) {
      validateCredentialSets(dcqlQuery.getCredentialSets(), dcqlQuery.getCredentials(), result);
    }

    // 4. 전체적인 일관성 검증
    validateConsistency(dcqlQuery, result);


    return result;
  }

  /**
   * DCQL 쿼리의 기본 구조 검증
   */
  private static void validateBasicStructure(DCQLQuery dcqlQuery, ValidationResult result) {
    // credentials 또는 credential_sets 중 하나는 반드시 있어야 함
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
   * Credentials 배열 검증
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

      // ID 중복 검사
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
   * 개별 Credential 검증
   */
  private static void validateCredential(DCQLQuery.CredentialQuery credential, String context, ValidationResult result) {
    if (credential == null) {
      result.addError(context + " is null");
      return;
    }

    // 필수 필드 검증
    validateRequiredField(credential.getId(), "id", context, result);
    validateRequiredField(credential.getFormat(), "format", context, result);

    // ID 형식 검증
    if (credential.getId() != null) {
      validateCredentialId(credential.getId(), context, result);
    }

    // 포맷 검증
    if (credential.getFormat() != null) {
      validateFormat(credential.getFormat(), context, result);
    }

    // Claims 검증
    if (credential.getClaims() != null) {
      validateClaims(credential.getClaims(), context, result);
    }

    // Claim Sets 검증
    if (credential.getClaimSets() != null) {
      validateCredentialClaimSets(credential.getClaimSets(), context, result);

      // claims와 claim_sets 동시 존재 시 경고
      if (credential.getClaims() != null) {
        result.addWarning(context + " has both 'claims' and 'claim_sets' - claim_sets takes precedence");
      }
    }

    // Meta 검증
    if (credential.getMeta() != null) {
      validateMeta(credential.getMeta(), context, result);
    }
  }

  /**
   * Claims 배열 검증
   */
  private static void validateClaims(List<DCQLQuery.ClaimQuery> claims, String context, ValidationResult result) {
    for (int i = 0; i < claims.size(); i++) {
      DCQLQuery.ClaimQuery claim = claims.get(i);
      String claimContext = context + ".claims[" + i + "]";

      if (claim == null) {
        result.addError(claimContext + " is null");
        continue;
      }

      // Path 필수
      if (claim.getPath() == null || claim.getPath().isEmpty()) {
        result.addError(claimContext + ".path is required and cannot be empty");
      } else {
        validatePath(claim.getPath(), claimContext + ".path", result);
      }

      // Values 검증 (선택적)
      if (claim.getValues() != null) {
        validateValues(claim.getValues(), claimContext + ".values", result);
      }
    }
  }

  /**
   * Path 검증
   */
  private static void validatePath(List<Object> path, String context, ValidationResult result) {
    if (!DCQLPathProcessor.isValidPath(path)) {
      result.addError(context + " contains invalid elements");
    }

    for (int i = 0; i < path.size(); i++) {
      Object element = path.get(i);
      if (element == null) {
        // null은 배열의 모든 요소를 의미하므로 허용
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
   * Values 배열 검증
   */
  private static void validateValues(List<Object> values, String context, ValidationResult result) {
    if (values.isEmpty()) {
      result.addWarning(context + " is empty - no value restrictions will be applied");
    }

    // 값들의 타입 일관성 검사
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
   * Credential Sets 검증
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
   * 개별 Credential Set 검증
   */
  private static void validateCredentialSet(DCQLQuery.CredentialSet credentialSet,
      String context,
      Set<String> availableCredentialIds,
      ValidationResult result) {
    if (credentialSet == null) {
      result.addError(context + " is null");
      return;
    }

    // Options 필수
    if (credentialSet.getOptions() == null || credentialSet.getOptions().isEmpty()) {
      result.addError(context + ".options is required and cannot be empty");
      return;
    }

    // 각 옵션 검증
    for (int i = 0; i < credentialSet.getOptions().size(); i++) {
      List<String> option = credentialSet.getOptions().get(i);
      String optionContext = context + ".options[" + i + "]";

      if (option == null || option.isEmpty()) {
        result.addError(optionContext + " cannot be null or empty");
        continue;
      }

      // 옵션 내 credential ID들이 실제로 정의되어 있는지 확인
      for (String credentialId : option) {
        if (!availableCredentialIds.contains(credentialId)) {
          result.addError(optionContext + " references undefined credential ID: " + credentialId);
        }
      }
    }
  }

  /**
   * 전체적인 일관성 검증
   */
  private static void validateConsistency(DCQLQuery dcqlQuery, ValidationResult result) {
    // Credential ID 유일성 검사는 이미 validateCredentials에서 수행됨

    // 추가적인 일관성 검사들...
    // 예: claim_sets에서 참조하는 claim ID들이 실제로 정의되어 있는지 등
  }

  // Helper 메서드들
  private static void validateRequiredField(String value, String fieldName, String context, ValidationResult result) {
    if (value == null || value.trim().isEmpty()) {
      result.addError(context + "." + fieldName + " is required");
    }
  }

  private static void validateCredentialId(String id, String context, ValidationResult result) {
    // OpenID4VP Section 6.1의 ID 규칙: alphanumeric, underscore, hyphen만 허용
    if (!id.matches("^[a-zA-Z0-9_-]+$")) {
      result.addError(context + ".id must contain only alphanumeric characters, underscores, and hyphens");
    }
  }

  private static void validateFormat(String format, String context, ValidationResult result) {
    // 지원하는 포맷 목록
    Set<String> supportedFormats = Set.of(
        "dc+sd-jwt", "vc+sd-jwt", "sd-jwt",
        "jwt_vc_json", "jwt_vc", "ldp_vc"
    );

    if (!supportedFormats.contains(format)) {
      result.addWarning(context + ".format '" + format + "' may not be supported");
    }
  }

  private static void validateMeta(Map<String, Object> meta, String context, ValidationResult result) {
    // 메타데이터 검증 (현재는 기본적인 검사만)
    if (meta.isEmpty()) {
      result.addWarning(context + ".meta is empty");
    }

    // vct_values 검증
    if (meta.containsKey("vct_values")) {
      Object vctValues = meta.get("vct_values");
      if (!(vctValues instanceof List)) {
        result.addError(context + ".meta.vct_values must be an array");
      }
    }
  }

  private static void validateCredentialClaimSets(List<DCQLQuery.ClaimSet> claimSets, String context, ValidationResult result) {
    // Claim Sets 검증 로직 (현재는 기본적인 검사만)
    if (claimSets.isEmpty()) {
      result.addError(context + ".claim_sets cannot be empty");
    }

    for (int i = 0; i < claimSets.size(); i++) {
      DCQLQuery.ClaimSet claimSet = claimSets.get(i);
      if (claimSet == null) {
        result.addError(context + ".claim_sets[" + i + "] cannot be null");
        continue;
      }

      // ClaimSet의 claims 검증
      if (claimSet.getClaims() == null || claimSet.getClaims().isEmpty()) {
        result.addError(context + ".claim_sets[" + i + "].claims cannot be null or empty");
      }
    }
  }

  /**
   * 검증 결과를 담는 클래스
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