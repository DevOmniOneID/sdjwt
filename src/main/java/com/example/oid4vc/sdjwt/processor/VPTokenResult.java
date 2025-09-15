package com.example.oid4vc.sdjwt.processor;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * VP Token 생성 결과 정보를 담는 DTO
 *
 * @author OmniOne Open DID
 * @version 1.0
 * @since 1.0
 */
@Data
@Builder
public class VPTokenResult {

  /** 생성된 VP Token JSON 문자열 */
  private String vpToken;

  /** 생성 성공 여부 */
  @Builder.Default
  private boolean success = true;

  /** 오류 메시지 (실패 시) */
  private String errorMessage;

  /** 경고 메시지 목록 */
  @Builder.Default
  private List<String> warnings = new ArrayList<>();

  /** 처리 결과 메타데이터 */
  @Builder.Default
  private Map<String, Object> metadata = new HashMap<>();

  /** 선택적 공개 통계 */
  private SelectiveDisclosureProcessor.SelectiveDisclosureStats disclosureStats;

  /** 생성 시점 */
  @Builder.Default
  private Instant createdAt = Instant.now();

  /** 처리 시간 (밀리초) */
  private Long processingTimeMs;

  /** 원본 요청 정보 */
  private VPTokenRequest originalRequest;

  /**
   * 성공 결과 생성
   */
  public static VPTokenResult success(String vpToken) {
    return VPTokenResult.builder()
        .vpToken(vpToken)
        .success(true)
        .build();
  }

  /**
   * 성공 결과 생성 (상세 정보 포함)
   */
  public static VPTokenResult success(String vpToken,
      SelectiveDisclosureProcessor.SelectiveDisclosureStats stats) {
    return VPTokenResult.builder()
        .vpToken(vpToken)
        .success(true)
        .disclosureStats(stats)
        .build();
  }

  /**
   * 실패 결과 생성
   */
  public static VPTokenResult failure(String errorMessage) {
    return VPTokenResult.builder()
        .success(false)
        .errorMessage(errorMessage)
        .build();
  }

  /**
   * 실패 결과 생성 (예외 기반)
   */
  public static VPTokenResult failure(String errorMessage, Throwable cause) {
    return VPTokenResult.builder()
        .success(false)
        .errorMessage(errorMessage + ": " + cause.getMessage())
        .build();
  }

  /**
   * 경고 추가
   */
  public VPTokenResult addWarning(String warning) {
    if (warnings == null) {
      warnings = new java.util.ArrayList<>();
    }
    warnings.add(warning);
    return this;
  }

  /**
   * 메타데이터 추가
   */
  public VPTokenResult addMetadata(String key, Object value) {
    if (metadata == null) {
      metadata = new java.util.HashMap<>();
    }
    metadata.put(key, value);
    return this;
  }

  /**
   * 처리 시간 설정
   */
  public VPTokenResult withProcessingTime(long startTimeMs) {
    this.processingTimeMs = System.currentTimeMillis() - startTimeMs;
    return this;
  }

  /**
   * 원본 요청 정보 설정
   */
  public VPTokenResult withOriginalRequest(VPTokenRequest request) {
    this.originalRequest = request;
    return this;
  }

  /**
   * 결과 요약
   */
  public String getSummary() {
    if (!success) {
      return "FAILED: " + errorMessage;
    }

    StringBuilder summary = new StringBuilder("SUCCESS");

    if (disclosureStats != null) {
      summary.append(" - ").append(disclosureStats.getSummary());
    }

    if (warnings != null && !warnings.isEmpty()) {
      summary.append(" (").append(warnings.size()).append(" warnings)");
    }

    if (processingTimeMs != null) {
      summary.append(" [").append(processingTimeMs).append("ms]");
    }

    return summary.toString();
  }

  /**
   * 상세 정보 포함 여부
   */
  public boolean hasDetailedInfo() {
    return disclosureStats != null ||
        (metadata != null && !metadata.isEmpty()) ||
        (warnings != null && !warnings.isEmpty());
  }

  /**
   * VP Token 유효성 확인
   */
  public boolean hasValidVPToken() {
    return success && vpToken != null && !vpToken.trim().isEmpty();
  }
}