package com.Modu.Stock.repository;

import com.Modu.Stock.dto.QUserBoardDto;
import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.Board;
import com.Modu.Stock.entity.QBoard;
import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.service.BoardService;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

import static com.Modu.Stock.entity.QBoard.*;
import static com.Modu.Stock.entity.security.QUser.*;
import static org.assertj.core.api.Assertions.*;



@Transactional
@SpringBootTest
class UserRepositoryTest {

    @Autowired
    JPAQueryFactory queryFactory;

    @Autowired
     BoardService boardService;



    @Test
    @DisplayName("querydsl을 이용하여, user,board inner join 으로 조회")
    public void findAllByWithBoardV1(){

        //given
        Board board = Board.createBoard("dobi", "dobi", LocalDateTime.now());
        String username = "123"; // username = 123으로 미리 저장해 놓음
        Board saveBoard = boardService.save(username, board);

        //when
        List<User> findUser = queryFactory
                .selectFrom(user)
                .innerJoin(user.boards, QBoard.board)
                .fetch();
        //then
        assertThat(findUser.size()).isEqualTo(1);

        assertThat(findUser)
                .extracting("username")
                .containsExactly("123");

        assertThat(findUser)
                .flatExtracting("boards")
                .extracting("title")
                .contains("dobi");
    }

    @Test
    @DisplayName("user,board inner join 으로 조회")
    public void findAllByWithBoardV2(){

        //given
        Board board = Board.createBoard("dobi", "dobi", LocalDateTime.now());
        String username = "123"; // username = 123으로 미리 저장해 놓음
        Board saveBoard = boardService.save(username, board);

        //when
        List<UserBoardDto> findUser = queryFactory
                .select(new QUserBoardDto(
                        user.id,
                        user.username,
                        user.password,
                        user.enabled,
                        user.email,
                        user.createDate,
                        QBoard.board.id,
                        QBoard.board.title,
                        QBoard.board.content))
                .from(user)
                .innerJoin(user.boards,QBoard.board)
                .fetch();
        //then
        assertThat(findUser.size()).isEqualTo(1);

        assertThat(findUser)
                .extracting("username")
                .containsExactly("123");

        assertThat(findUser)
                .extracting("username", "title")
                .contains(tuple("123", "dobi"));

    }

}