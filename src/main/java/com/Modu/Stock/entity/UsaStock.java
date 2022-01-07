package com.Modu.Stock.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static lombok.AccessLevel.*;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
public class UsaStock {

    @Id
    @GeneratedValue
    @Column(name = "usaStock_id")
    private Long id;

    private String title;
    private String writer;
    private int views;

    private LocalDateTime createDate;
    private LocalDateTime updateDate;

    @OneToMany(mappedBy = "usaStock")
    private List<Likes> likes = new ArrayList<>();


}
