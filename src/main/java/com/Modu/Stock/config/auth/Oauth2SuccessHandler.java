package com.Modu.Stock.config.auth;

import com.Modu.Stock.config.jwt.SecretKey;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;

@Slf4j
@Getter
@RequiredArgsConstructor
@Component
public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {

    private final SecretKey key;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        PrincipalDetails oauth2User = (PrincipalDetails) authentication.getPrincipal();

        /**
         * Header 설정
         */
        HashMap<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", "HS256");

        /**
         * payload 설정
         */
        HashMap<String, Object> payloads = new HashMap<>();
        payloads.put("id", oauth2User.getUser().getId());
        payloads.put("username", oauth2User.getUser().getUsername());


        //토큰 유효 시간
        Long expiredTime = 30 * 60 * 1000L; //30분
        Date expired = new Date();
        expired.setTime(expired.getTime() + expiredTime);



        //시크릿 키 생성
        String algorithm = SignatureAlgorithm.HS256.getJcaName();
        log.info("secretKey = {}", key);
        String secretKey = key.getSecretKey();

        byte[] byteSecretKey = DatatypeConverter.parseBase64Binary(secretKey);

        Key secretKeySpec = new SecretKeySpec(byteSecretKey, algorithm);


        /**
         * RSA 방식이 아닌 hash 암호방식 토큰 생성
         */
        String jwtToken = Jwts.builder()
                .setHeader(headers) //headers 설정
                .setClaims(payloads) //payloads 설정
                .setSubject("user") //토큰 용도
                .setExpiration(expired) //토큰 만료 시간 설정
                .signWith(secretKeySpec,SignatureAlgorithm.HS256)
                .compact();

        response.addHeader("Authorization","Bearer " + jwtToken);

        log.info("addHeader = {}", response.getHeaderNames());
        log.info("addHeader = {}", response.getHeader("Authorization"));

        log.info("successfulAuthentication 함수 실행");
    }

    }

