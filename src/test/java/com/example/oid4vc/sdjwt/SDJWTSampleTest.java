package com.example.oid4vc.sdjwt;

import com.example.oid4vc.sdjwt.core.Disclosure;
import com.example.oid4vc.sdjwt.core.SDJWT;
import com.example.oid4vc.sdjwt.oid4vci.OID4VCIssuer;
import com.example.oid4vc.sdjwt.oid4vp.OID4VPHandler;
import com.example.oid4vc.sdjwt.verifier.SDJWTVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Set;

/**
 * 완전한 SD-JWT VC 샘플 생성 및 VP 토큰 처리 테스트
 */
public class SDJWTSampleTest {

  @Test
  @DisplayName("Nation ID SD-JWT VC/VP 플로우 테스트")
  void SDJWTSampleTest() throws Exception {
    // =========== STEP 1: 키 생성 ===========
    System.out.println("키 페어 생성");
    ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
    ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

    PrivateKey issuerPrivateKey = issuerKey.toPrivateKey();
    PublicKey issuerPublicKey = issuerKey.toPublicKey();
    PrivateKey holderPrivateKey = holderKey.toPrivateKey();
    PublicKey holderPublicKey = holderKey.toPublicKey();
    
    System.out.println("Issuer 키 생성 완료");
    System.out.println("Holder 키 생성 완료");

    // =========== STEP 2: SD-JWT VC 발급 ===========
    System.out.println("SD-JWT VC 발급");
    
    // 발급자 생성
    OID4VCIssuer issuer = new OID4VCIssuer(
        issuerPrivateKey,
        "did:omn:issuer"
    );

    // 신원 정보 (모든 필드가 선택적 공개 가능)
    Map<String, Object> identityInfo = Map.of(
        "given_name", "Raon",
        "family_name", "Kim",
        "birth_date", "1990-01-01",
        "gender", "male",
        "nationality", "KR",
        "id_number", "900101-1234567",
        "address", Map.of(
            "country", "대한민국",
            "region", "서울특별시",
            "locality", "강남구",
            "street_address", "테헤란로 123"
        ),
        "phone_number", "+82-10-1234-5678",
        "email", "raonkim@raoncorp.com"
    );

    // SD-JWT VC 발급
    String identityVC = issuer.issueCredential(
        "https://credentials.gov.kr/identity_credential",
        identityInfo,
        holderPublicKey
    );

    System.out.println("발급된 SD-JWT VC:");
    System.out.println("   " + identityVC);
    System.out.println();

    // =========== STEP 3: SD-JWT 구조 분석 ===========
    System.out.println("SD-JWT 구조 분석");
    
    SDJWT parsedVC = SDJWT.parse(identityVC);
    
    // JWT 헤더 및 페이로드 분석
    SignedJWT credentialJWT = SignedJWT.parse(parsedVC.getCredentialJwt());
    
    System.out.println("JWT 헤더: " + credentialJWT.getHeader().toJSONObject());
    System.out.println("JWT 페이로드: " + credentialJWT.getPayload().toString());
    System.out.println("총 Disclosure 개수: " + parsedVC.getDisclosureCount());
    
    // 각 Disclosure 상세 정보
    System.out.println("Disclosure 상세 정보:");
    for (int i = 0; i < parsedVC.getDisclosures().size(); i++) {
        Disclosure disclosure = parsedVC.getDisclosures().get(i);
        System.out.println("     " + (i+1) + ". " + disclosure.getClaimName() + ": " + disclosure.getClaimValue());
        System.out.println("        Salt: " + disclosure.getSalt());
        System.out.println("        Digest: " + disclosure.digest());
        System.out.println("        Raw: " + disclosure.getDisclosure());
    }
    System.out.println();

    // =========== STEP 4: 선택적 공개 VP 토큰 생성 ===========
    System.out.println("선택적 공개 VP 토큰 생성");

    Set<String> onlyRequiredClaims = Set.of("given_name", "family_name", "birth_date");
    
    String vpToken = OID4VPHandler.createVPToken(
        identityVC,
        onlyRequiredClaims,
        holderPrivateKey,
        "did:omn:issuer",
        "test-nonce-123"
    );
    
    System.out.println("VP Token (이름, 생년월일만 공개):");
    System.out.println("   " + vpToken);
    System.out.println();

    // =========== STEP 5: VP 토큰 검증 ===========
    System.out.println("VP 토큰 검증");
    
    SDJWTVerifier verifier = new SDJWTVerifier(issuerPublicKey, holderPublicKey);
    
    // VP 검증
    SDJWTVerifier.SDJWTClaimsSet bankClaims = verifier.verify(
        vpToken,
        "did:omn:issuer",
        "test-nonce-123"
    );
    
    System.out.println("VP 검증 결과:");
    bankClaims.getClaims().forEach((key, value) -> {
        if (!key.startsWith("_") && !key.equals("iss") && !key.equals("iat") && 
            !key.equals("exp") && !key.equals("vct") && !key.equals("cnf")) {
            System.out.println("     " + key + ": " + value);
        }
    });

    // =========== STEP 6: Key Binding JWT 분석 ===========
    System.out.println("Key Binding JWT 분석");
    
    SDJWT parsedBankVP = SDJWT.parse(vpToken);
    if (parsedBankVP.hasKeyBindingJwt()) {
        SignedJWT keyBindingJWT = SignedJWT.parse(parsedBankVP.getKeyBindingJwt());
        System.out.println("Key Binding JWT 헤더: " + keyBindingJWT.getHeader().toJSONObject());
        System.out.println("Key Binding JWT 페이로드: " + keyBindingJWT.getPayload());
    }
    System.out.println();
  }
}