package com.Modu.Stock.config;

import com.Modu.Stock.config.jwt.JwtAuthenticationFilter;
import com.Modu.Stock.config.jwt.JwtAuthorizationFilter;
import com.Modu.Stock.config.jwt.SecretKey;
import com.Modu.Stock.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;


@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@RequiredArgsConstructor
//@EnableGlobalMethodSecurity(securedEnabled = true)//secured 어노테이션 활성화 @Secured("ROLE_ADMIN")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserRepository userRepository;
    private final SecretKey secretKey;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        /**
         * jwt 방식
         */
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()
                .httpBasic().disable();

        http
                .addFilter(new JwtAuthenticationFilter(authenticationManager(),secretKey)) //AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository,secretKey))
                .authorizeRequests()
                .antMatchers("/api/boards/**").hasRole("ADMIN")
                .and()
                .authorizeRequests()
                .antMatchers("/", "/account/**", "/css/**", "/api/**", "/board/**").permitAll()
//                .antMatchers("/user/**").authenticated()
//                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .anyRequest().authenticated()
                .and()
//                .formLogin()
//                .loginPage("/account/login")
//                .loginProcessingUrl("/account/login") //login 주소가 호출이 되면 시큐리티가 낚아채 준다.
//                .defaultSuccessUrl("/")
//                .permitAll()
//                .and()
                .logout()
                .permitAll();
                /**
                 *구글 로그인이 완료된 뒤의 후처리가 필요함 1.코드받기(인증), 2.엑세스토큰(권한)
                 *사용자 프로필 정보를 가져오고, 4.그 정보를 토대로 회원가입을 시키기도 함
                 */
//        http
//                .oauth2Login()
//                .loginPage("/account/login")
//                .userInfoEndpoint();
//                .userService(principalOauth2UserService);


    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
