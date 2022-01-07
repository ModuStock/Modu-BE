package com.Modu.Stock.dto;


import com.Modu.Stock.entity.security.User;
import lombok.*;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private Long id;

    @NotNull
    @Length(min = 3, max = 20)
    private String username;

    @NotNull
    @Length(min = 3, max = 20)
    private String password;
    private String email;
    private LocalDateTime createUserDate;

    private boolean enabled;

    private String provider;
    private String providerId;


    public UserDto(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public UserDto(User user) {
        this.id  = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.email = user.getEmail();
        this.createUserDate = user.getCreateDate();
    }









    public static UserDto  getUserOne(User user){
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .email(user.getEmail())
                .createUserDate(user.getCreateDate())
                .enabled(user.isEnabled())
                .provider(user.getProvider())
                .providerId(user.getProviderId())
                .build();

    }


}
