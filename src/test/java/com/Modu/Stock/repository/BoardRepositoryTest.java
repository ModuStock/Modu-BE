package com.Modu.Stock.repository;

import com.Modu.Stock.entity.Board;
import com.Modu.Stock.entity.QBoard;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.*;


@SpringBootTest
@Transactional
class BoardRepositoryTest {

    @Autowired
    BoardRepository boardRepository;

    @Autowired
    JPAQueryFactory queryFactory;

    @Test
    public void findByTitleOrContent(){
        //given
        Board board = Board.createBoard("dobi", "dobi", LocalDateTime.now());
        boardRepository.save(board);

        //when
        List<Board> result = queryFactory
                .selectFrom(QBoard.board)
                .where(QBoard.board.title.contains(board.getTitle()).or(QBoard.board.content.contains(board.getContent())))
                .offset(0)
                .limit(1)
                .orderBy(QBoard.board.id.desc())
                .fetch();


        JPAQuery<Board> countQuery = queryFactory
                .selectFrom(QBoard.board)
                .where(QBoard.board.title.eq(board.getTitle()).or(QBoard.board.content.eq(board.getContent())));

        Board findBoard = result.get(0);

        //then

        assertThat(findBoard).isEqualTo(board);




    }

}