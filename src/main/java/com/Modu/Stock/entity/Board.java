package com.Modu.Stock.entity;

import com.Modu.Stock.entity.security.User;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.time.LocalDateTime;

import static javax.persistence.FetchType.*;

@Entity
@Getter
@ToString(of = {"id, title, content, createDate"})
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Board {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "board_id")
    private Long id;


    private String title;
    private String content;

    private LocalDateTime createDate;


    @ManyToOne(fetch = LAZY)
    @JoinColumn(name = "user_id")
    private User user;


    protected Board(String title, String content, LocalDateTime localDateTime) {
        this.title = title;
        this.content = content;
        this.createDate = localDateTime;
    }

    public static Board createBoard(String title, String content, LocalDateTime localDateTime) {
        Board board = new Board(title, content, localDateTime);

        return board;
    }


    /**
     * 생성 메서드
     */
    public void addUser(User user) {
        this.user = user;
        user.getBoards().add(this);
    }


}
