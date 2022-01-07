package com.Modu.Stock.controller.api;

import com.Modu.Stock.config.auth.PrincipalDetails;
import com.Modu.Stock.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class LoginApiController {

    private final UserRepository userRepository;

    @GetMapping("/v1/user")
    public String user(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        log.info("principal = {}", principal);
        return "user";

    }


}
