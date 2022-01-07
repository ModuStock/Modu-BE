package com.Modu.Stock.config.jwt;

import com.Modu.Stock.config.auth.PrincipalDetails;
import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 시큐리티가 filter 를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 가 있음
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음
 * 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 타지않음
 */
@Slf4j
@Transactional(readOnly = true)
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {


    private final UserRepository userRepository;

    private SecretKey secret;



    @Autowired
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, SecretKey secretKey) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.secret = secretKey;

        log.info("JwtAuthorizationFilter constructor");

    }

    /**
     * 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증이나 권한이 필요한 주소 요청이 됨");

        String jwtHeader = request.getHeader("Authorization");
        log.info("jwtHeader = {}", jwtHeader);


        /**
         * header가 있는지 확인
         */
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);

            return;
        }

        /**
         * jwt 토큰을 검증을 해서 정상적인 사용자인지 확인
         */

        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        log.info("jwtToken = {}", jwtToken);

        String secretKey = secret.getSecretKey();


        log.info("secretKey= {}",secretKey);



        Claims claims = Jwts.parserBuilder()
                .setSigningKey(DatatypeConverter.parseBase64Binary(secretKey))
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
        log.info("claims = {}", claims);

        String username =(String) claims.get("username");


        log.info("Jwt Username = {}", username);
        // 서명이 정상적으로 됨

        if (username != null) {

            User userEntity = userRepository.findByUsername(username);


            List<String> collect = userEntity.getUserRoles()
                    .stream()
                    .map(u -> u.getRole().getName())
                    .collect(Collectors.toList());


            log.info("collet = {}", userEntity);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity,collect);

            log.info("principalDetails = {}", principalDetails.getUsername());

            //Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            log.info("authenticaiton = {}", authentication);

            //강제로 시큐리티의 세션에 접근하며 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("in authentication = {}", authentication);

            chain.doFilter(request,response);

        }



    }
}
