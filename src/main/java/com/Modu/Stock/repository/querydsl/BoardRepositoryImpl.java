package com.Modu.Stock.repository.querydsl;

import com.Modu.Stock.dto.QUserBoardDto;
import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.QBoard;
import com.Modu.Stock.entity.security.QUser;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

import java.util.List;

import static com.Modu.Stock.entity.QBoard.*;
import static com.Modu.Stock.entity.security.QUser.*;
import static org.springframework.util.StringUtils.hasText;

@RequiredArgsConstructor
@Slf4j
public class BoardRepositoryImpl implements BoardRepositoryCustom{


    private final JPAQueryFactory queryFactory;

    /**
     * 전체 게시글 조회
     */
    @Override
    public Page<UserBoardDto> findByListAll(String title, String content, Pageable pageable) {
        List<UserBoardDto> result = queryFactory
                .select(new QUserBoardDto(
                        user.id,
                        user.username,
                        board.id,
                        board.title,
                        board.content))
                .from(board)
                .leftJoin(board.user, user)
                .where(board.title.contains(title).or(board.content.contains(content)))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .orderBy(board.id.desc())
                .fetch();

        long countQuery = queryFactory
                .selectFrom(board)
                .leftJoin(board.user, user)
                .where(board.title.contains(title).or(board.content.contains(content)))
                .fetchCount();

        log.info("countQuery = {}", countQuery);

        return PageableExecutionUtils.getPage(result, pageable, () -> countQuery);

    }


    /**
     * 전체 게시글 조회 API
     */
    @Override
    public Page<UserBoardDto> findAllBoardApi(Pageable pageable) {
        List<UserBoardDto> result = queryFactory
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
                .from(board)
                .leftJoin(board.user, user)
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        long countQuery = queryFactory
                .selectFrom(board)
                .fetchCount();



        return PageableExecutionUtils.getPage(result, pageable, () -> countQuery);

    }


    /**
     * 내 게시글 조회
     */
    @Override
    public Page<UserBoardDto> findMyBoardList(Long id, Pageable pageable) {

        List<UserBoardDto> result = queryFactory
                .select(new QUserBoardDto(
                        user.id,
                        user.username,
                        board.id,
                        board.title,
                        board.content))
                .from(board)
                .innerJoin(board.user, user)
                .where(user.id.eq(id))
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        long countQuery = queryFactory
                .selectFrom(board)
                .innerJoin(board.user, user)
                .where(user.id.eq(id))
                .fetchCount();

        return PageableExecutionUtils.getPage(result,pageable,() -> countQuery);
    }



//    private BooleanExpression titleEq(String title) {
//        return hasText(title) ? board.title.like(title) : null;
//    }
//
//    private BooleanExpression contentEq(String content){
//        return hasText(content) ? board.content.like(content) : null;
//    }
}
