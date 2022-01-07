package com.Modu.Stock.controller.api;

import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.dto.UserDto;
import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.form.UserForm;
import com.Modu.Stock.service.UserService;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class UserApiController {

    private final UserService userService;


    /**
     * User, Board 엔티티를 inner join 으로 전체 조회후 반환 V1
     * select 쿼리 2번
     */
    @GetMapping("/users/v1")
    public Result allV1() {
        List<UserForm> userAndBoard = userService.findUserAndBoard();
        log.info("userService - userAndBoard");

        return new Result(userAndBoard.size(),userAndBoard);
    }

    /**
     * User, Board 엔티티를 inner join 으로 전체 조회후 반환 V2
     * 한방쿼리
     */
    @GetMapping("/users/v2")
    public Result allV2() {
        List<UserBoardDto> userAndBoardV2 = userService.findUserAndBoardV2();
        log.info("userService - userAndBoard");

        return new Result(userAndBoardV2.size(),userAndBoardV2);
    }



    /**
     * User ROLE_ADMIN 권한으로 회원가입
     * username, password, email 입력하면 ->  + id, createDate 반환
     */
    @PostMapping("/user/save")
    public UserDto newUser(@Valid @RequestBody UserDto user) {

        User createUser = User.createApiUser(user.getUsername(), user.getPassword(), user.getEmail());
        userService.adminJoin(createUser);
        UserDto userDto = new UserDto(createUser);

        return userDto;
    }


    /**
     * 회원 단건 조회
     */
    @GetMapping("user/{id}")
    public UserDto one(@PathVariable Long id) throws Exception {
        User user = userService.findById(id);

        UserDto userOne = UserDto.getUserOne(user);

        return userOne;

    }

    /**
     * 회원 전체 조회
     */
    @GetMapping("users/all")
    public Result findAll() {
        List<UserDto> findUsers = userService.findAll();

        return new Result(findUsers.size(), findUsers);
    }


    /**
     * Json으로 반환 시 [] -> {}
     */
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    static class Result<T>{
        private int count;
        private T data;

        public Result(T data) {
            this.data = data;
        }
    }


}
