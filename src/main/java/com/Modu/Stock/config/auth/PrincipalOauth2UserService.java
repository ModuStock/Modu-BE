package com.Modu.Stock.config.auth;

import com.Modu.Stock.config.auth.provider.FacebookUserInfo;
import com.Modu.Stock.config.auth.provider.GoogleUserInfo;
import com.Modu.Stock.config.auth.provider.NaverUserInfo;
import com.Modu.Stock.config.auth.provider.Oauth2UserInfo;
import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.entity.security.UserRole;
import com.Modu.Stock.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.Modu.Stock.entity.security.Role.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;



    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    @Transactional
   @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
       log.info("getClientRegistration = {}", userRequest.getClientRegistration());// 어떤 OAuth로 로그인 하였는지 확인가능
       log.info("getAccessToken = {}", userRequest.getAccessToken().getTokenValue());
       /**
        * 구글 로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code를 리턴(OAuth-client 라이브러리) ->AccessToken 요청
        * userRequest 정보 -> 회원프로필 받아야함(loadUser 함수) -> 구글로부터 회원 프로필을 받아준다.
        */
       OAuth2User oAuth2User = super.loadUser(userRequest);
       log.info("getAttributes = {}", oAuth2User.getAttributes());

        Oauth2UserInfo oauth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oauth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("페이스북 로그인 요청");
            oauth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            oauth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
            log.info("네이버 로그인 요청");

        } else {
            log.info("허용되지 않은 접근 입니다.");
        }

       String provider = oauth2UserInfo.getProvider(); //google, facebook
       String providerId = oauth2UserInfo.getProviderId(); //google,facebook primary Key
       String username = provider + "_" + providerId;
       String passwordEncode = UUID.randomUUID().toString();
       String password = passwordEncoder.encode(passwordEncode);
       String email = oauth2UserInfo.getEmail();
       UserRole userRole = UserRole.addRole(USER);
       LocalDateTime createDate = LocalDateTime.now();


        User userEntity = userRepository.findByUsername(username);

       log.info("username = {}", userEntity);
       if (userEntity == null) {
            userEntity = User.builder()
                   .username(username)
                   .password(password)
                   .email(email)
                   .provider(provider)
                   .providerId(providerId)
                   .userRole(userRole)
                   .createDate(createDate)
                   .enabled(true)
                   .build();

            log.info("PrincipalOauth2 userEntity = {]", userEntity);

           userRepository.save(userEntity);

           log.info("Oauth2 Join = {}", userEntity);
       } else {
           List<String> collect = userEntity.getUserRoles()
                   .stream()
                   .map(u -> u.getRole().getName())
                   .collect(Collectors.toList());
           log.info("collect = {}", collect);
           return new PrincipalDetails(userEntity, collect, oAuth2User.getAttributes());
       }


       return super.loadUser(userRequest);
    }
}
