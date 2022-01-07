package com.Modu.Stock.service;

import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.dto.UserDto;
import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.entity.security.UserRole;
import com.Modu.Stock.form.UserForm;
import com.Modu.Stock.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import static com.Modu.Stock.entity.security.Role.*;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;


    /**
     * User 회원가입
     */
    @Transactional
    public void userJoin(User user) {
        log.info("USER SERVICE IN");
        //클라이언트에서 회원 가입시 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        log.info("encoder success");

        UserRole userRole = UserRole.addUserRole(user, USER);
        log.info("save userRole = {}", userRole);
        LocalDateTime createDate = LocalDateTime.now();

        user.signUp(user.getUsername(), encodedPassword, userRole, true, createDate, user.getEmail());
        log.info("signup");


        log.info("Before Save user = {}", user);
        userRepository.save(user);
        log.info("After Save user = {}", user);
    }


    /**
     * admin 회원가입
     * 추후에 분리 예정
     */
    @Transactional
    public void adminJoin(User admin) {

        String encodedPassword = passwordEncoder.encode(admin.getPassword());

        UserRole userRole = UserRole.addUserRole(admin, ADMIN);

        LocalDateTime createDate = LocalDateTime.now();

        admin.signUp(admin.getUsername(), encodedPassword, userRole,true, createDate, admin.getEmail());

        userRepository.save(admin);




    }

    /**
     * User, Board join
     * V1
     */
    public List<UserForm> findUserAndBoard() {

        //User, Board fetch join
        List<User> findUser = userRepository.findAllByWithBoardV1();
        log.info("findAllByWithBoard");

        //User 리스트를 DTO로 변환후 리스트로 반환
        List<UserForm> collect = findUser.stream()
                .map(user -> new UserForm(user))
                .collect(Collectors.toList());

        return collect;


    }

    /**
     * User, Board join
     * V2
     */
    public List<UserBoardDto> findUserAndBoardV2(){

        return userRepository.findAllByWithBoardV2();
    }


    /**
     * 단건 조회
     */
    public User findById(Long id) throws Exception {
        return userRepository.findById(id).orElseThrow(Exception::new);
    }


    /**
     * 전체 조회
     */
    public List<UserDto> findAll() {
        List<User> all = userRepository.findAll();

        List<UserDto> collect = all.stream()
                .map(user -> UserDto.getUserOne(user))
                .collect(Collectors.toList());
        return collect;

    }





}
