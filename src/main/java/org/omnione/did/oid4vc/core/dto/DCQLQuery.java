package org.omnione.did.oid4vc.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * DCQL (Digital Credentials Query Language) Query DTO
 * Based on OpenID4VP 1.0 Section 6
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
//@Schema(description = "DCQL Query object as defined in OpenID4VP 1.0 Section 6")
public class DCQLQuery {

  @JsonProperty("credentials")
  //@Schema(description = "Array of Credential Queries", required = true)
  private List<CredentialQuery> credentials;

  @JsonProperty("credential_sets")
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  //@Schema(description = "Array of credential set queries for additional constraints")
  private List<CredentialSet> credentialSets;

  @JsonProperty("transaction_data")
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  //Schema(description = "Transaction data for authorization")
  private List<Map<String, Object>> transactionData;

  /**
   * Credential Query
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class CredentialQuery {

    @JsonProperty("id")
    //@Schema(description = "Unique identifier for this credential query", required = true)
    private String id;

    @JsonProperty("format")
    //@Schema(description = "Credential format", example = "jwt_vc_json")
    private String format;

    @JsonProperty("meta")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    //@Schema(description = "Format-specific metadata")
    private Map<String, Object> meta;

    @JsonProperty("claims")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    //@Schema(description = "Array of claim queries")
    private List<ClaimQuery> claims;

    @JsonProperty("claim_sets")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    //@Schema(description = "Array of claim set queries")
    private List<ClaimSet> claimSets;

    @JsonProperty("purpose")
    //@Schema(description = "Purpose of the credential request")
    private String purpose;

    @JsonProperty("require_cryptographic_holder_binding")
    //@Schema(description = "Whether cryptographic holder binding is required", defaultValue = "true")
    private Boolean requireCryptographicHolderBinding;
  }

  /**
   * Claim Query
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class ClaimQuery {

    @JsonProperty("id")
    //@Schema(description = "Unique identifier for this claim query")
    private String id;

    @JsonProperty("path")
    //@Schema(description = "JSON path to the claim", required = true)
    private List<Object> path;

    @JsonProperty("purpose")
    //@Schema(description = "Purpose of requesting this claim")
    private String purpose;

    @JsonProperty("values")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    //@Schema(description = "Acceptable values for the claim")
    private List<Object> values;

    @JsonProperty("value")
    //@Schema(description = "Single acceptable value for the claim")
    private Object value;

    @JsonProperty("max")
    //@Schema(description = "Maximum value (inclusive)")
    private Object max;

    @JsonProperty("min")
    //@Schema(description = "Minimum value (inclusive)")
    private Object min;
  }

  /**
   * Claim Set
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class ClaimSet {

    @JsonProperty("id")
    //@Schema(description = "Unique identifier for this claim set", required = true)
    private String id;

    @JsonProperty("claims")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    //@Schema(description = "Array of claim queries in this set", required = true)
    private List<ClaimQuery> claims;

    @JsonProperty("purpose")
    //@Schema(description = "Purpose of this claim set")
    private String purpose;
  }

  /**
   * Credential Set
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class CredentialSet {

    @JsonProperty("id")
    //@Schema(description = "Unique identifier for this credential set", required = true)
    private String id;

    @JsonProperty("options")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    //@Schema(description = "Array of arrays containing credential IDs", required = true)
    private List<List<String>> options;

    @JsonProperty("purpose")
    //@Schema(description = "Purpose of this credential set")
    private String purpose;
  }
}