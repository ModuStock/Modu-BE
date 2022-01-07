package com.Modu.Stock.repository.querydsl;

import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.security.User;

import java.util.List;

public interface UserRepositoryCustom {

    List<User> findAllByWithBoardV1();

    List<UserBoardDto> findAllByWithBoardV2();
}
