package com.Modu.Stock.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.Modu.Stock.config.auth.PrincipalDetails;
import com.Modu.Stock.entity.security.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


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


/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
 * login 요청해서 username, password 전송하면 (Post)
 * 이 필터가 동작
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final SecretKey key;





    /**
     * login 요청을 하면 로그인 시도를 위해서 실행되는 함수
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("AuthenticationFilter 로그인 시도중");

        //1. username, password 받아서

        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                log.info("input = {}",input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            log.info("user = {}", user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            /**
             *  PrincipalDetailsService loadUserByUsername실행
             *  authentication에는 로그인 한 정보가 담김
             */
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            /**
             * authentication 객체가 session 영역에 저장됨 => 로그인이 되었다는 뜻
             */
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            log.info("getUsername = {}",principalDetails.getUser().getUsername());

            /**
             * authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return을 해 주는것
             * 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거다.
             * 굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없음 근데 단지 권한 처리때문에 session에 넣어주는 것이다.
             */

            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;

    }

    /**
     *  attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication함수가 실행됨
     *  jwt 토큰을 만들어서 request요청한 사용자에게 jwt토큰을 response해주면 됨
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {



        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

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
        payloads.put("id", principalDetails.getUser().getId());
        payloads.put("username", principalDetails.getUser().getUsername());


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
