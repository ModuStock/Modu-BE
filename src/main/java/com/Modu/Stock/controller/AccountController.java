package com.Modu.Stock.controller;

import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.repository.RoleRepository;
import com.Modu.Stock.repository.UserRoleRepository;
import com.Modu.Stock.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/account")
@RequiredArgsConstructor
@Slf4j
public class AccountController {

    private final UserService userService;
    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;

    @GetMapping("/login")
    public String login() {
        log.info("login AccountController");
        return "account/login";
    }


    @GetMapping("/register")
    public String getRegister(@ModelAttribute(name = "user") User user){
        return "account/register";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute(name = "user") User user) {

        log.info("in account Controller");

        userService.userJoin(user);

        log.info("success userService.save");
        return "redirect:/";
    }
}
