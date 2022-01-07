package com.Modu.Stock.config.auth;

import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 시큐리티 설정에서 loginProcessingUrl("/login");
 * login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어 있는 loadUserByUsername 실행
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    /**
     * 시큐리티 session = Authentication = UserDetails
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("UserDetailsService In");
        User userEntity = userRepository.findByUsername(username);

        List<String> collect = userEntity.getUserRoles()
                .stream()
                .map(u -> u.getRole().getName())
                .collect(Collectors.toList());


        log.info("userEntity = {}", userEntity);

        if (userEntity != null) {
            return new PrincipalDetails(userEntity,collect);
        }
        return null;
    }


}
