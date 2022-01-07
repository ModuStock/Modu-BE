package com.Modu.Stock.dto;


import com.querydsl.core.annotations.QueryProjection;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class UserBoardDto {



    private Long userId;
    private String username;
    private String password;
    private boolean enabled;
    private String email;
    private LocalDateTime createDate;
    private Long boardId;
    private String title;
    private String content;


    @QueryProjection
    public UserBoardDto(Long userId, String username, String password, boolean enabled, String email, LocalDateTime createDate, Long boardId, String title, String content) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.email = email;
        this.createDate = createDate;
        this.boardId = boardId;
        this.title = title;
        this.content = content;
    }

    @QueryProjection
    public UserBoardDto(Long id,String username, Long boardId, String title, String content) {
        this.userId = id;
        this.username = username;
        this.boardId = boardId;
        this.title = title;
        this.content = content;
    }

    @QueryProjection
    public UserBoardDto(Long id,Long boardId, String title, String content) {
        this.userId = id;
        this.boardId = boardId;
        this.title = title;
        this.content = content;
    }
}
