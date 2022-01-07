package com.Modu.Stock.entity;

import com.Modu.Stock.entity.security.User;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

import static javax.persistence.FetchType.*;
import static javax.persistence.GenerationType.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Likes {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "likes_id")
    private Long id;

    @ManyToOne(fetch = LAZY)
    @JoinColumn(name = "koreaStock_id")
    private KoreaStock koreaStock;

    @ManyToOne(fetch = LAZY)
    @JoinColumn(name = "usaStock_id")
    private UsaStock usaStock;


    @ManyToOne(fetch = LAZY)
    @JoinColumn(name = "user_id")
    private User user;


}
