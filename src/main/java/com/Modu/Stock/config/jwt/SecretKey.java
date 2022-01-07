package com.Modu.Stock.config.jwt;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class SecretKey {


    public static String secretKey;


    @Value("${spring.jwt.secret}")
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public SecretKey(@Value("${spring.jwt.secret}")String value) {
        this.secretKey = value;
    }

    public String getSecretKey() {
        return secretKey;
    }




}
