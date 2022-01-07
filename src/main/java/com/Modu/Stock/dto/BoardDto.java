package com.Modu.Stock.dto;

import com.Modu.Stock.entity.Board;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class BoardDto {



    private Long id;

    @NotNull
    @Size(min = 2, max = 20, message = "제목은 2자이상 30자 이하입니다.")
    private String title;

    @NotNull
    @Size(min = 1, max = 500)
    private String content;







    public BoardDto(Board board) {

        this.id = board.getId();
        this.title = board.getTitle();
        this.content = board.getContent();
        log.info(" in BoardForm Constructor");
    }


}
