package com.Modu.Stock.repository;

import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.repository.querydsl.UserRepositoryCustom;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long>, UserRepositoryCustom {

     User findByUsername(String username);

}
