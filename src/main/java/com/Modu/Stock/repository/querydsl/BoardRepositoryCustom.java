package com.Modu.Stock.repository.querydsl;

import com.Modu.Stock.dto.UserBoardDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface BoardRepositoryCustom {
    //내 게시글 조회
    Page<UserBoardDto> findMyBoardList(Long id, Pageable pageable);

    //전체 게시글 조회
    Page<UserBoardDto> findByListAll(String title, String content, Pageable pageable);

    //전체 게시글 조회 API
    Page<UserBoardDto> findAllBoardApi(Pageable pageable);
}
