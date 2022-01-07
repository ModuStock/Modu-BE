package com.Modu.Stock.form;

import com.Modu.Stock.dto.BoardDto;
import com.Modu.Stock.entity.security.User;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;


@Getter
@Setter
@Slf4j
@ToString
public class UserForm {

    private Long id;
    private String username;
    private String password;
    private boolean enabled;

    private String email;

    private LocalDateTime createDate;

    private List<BoardDto> boards;


    /**
     * 컬렉션 객체인 Board -> BoardForm으로 변환
     */
    public UserForm(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.enabled = user.isEnabled();
        this.email = user.getEmail();
        this.createDate = user.getCreateDate();
        this.boards = user.getBoards().stream()
                .map(board -> new BoardDto(board))
                .collect(Collectors.toList());

        log.info("UserFormConstructor in = {}", this);
    }
}
