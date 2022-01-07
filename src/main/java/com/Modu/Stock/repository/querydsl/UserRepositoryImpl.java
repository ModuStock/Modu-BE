package com.Modu.Stock.repository.querydsl;


import com.Modu.Stock.dto.QUserBoardDto;
import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.QBoard;
import com.Modu.Stock.entity.security.QUser;
import com.Modu.Stock.entity.security.User;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;

import java.util.List;

import static com.Modu.Stock.entity.QBoard.*;
import static com.Modu.Stock.entity.security.QUser.*;


@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepositoryCustom{


    private final JPAQueryFactory queryFactory;



    @Override
    public List<User> findAllByWithBoardV1() {

        return queryFactory
                .select(user)
                .distinct()
                .from(user)
                .innerJoin(user.boards,board)
                .fetch();

    }

    @Override
    public List<UserBoardDto> findAllByWithBoardV2() {
        return queryFactory
                .select(new QUserBoardDto(
                        user.id,
                        user.username,
                        user.password,
                        user.enabled,
                        user.email,
                        user.createDate,
                        board.id,
                        board.title,
                        board.content))
                .from(user)
                .innerJoin(user.boards,board)
                .fetch();
    }
}
