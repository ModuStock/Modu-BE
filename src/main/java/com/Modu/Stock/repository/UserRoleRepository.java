package com.Modu.Stock.repository;

import com.Modu.Stock.entity.security.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRoleRepository extends JpaRepository<UserRole,Long> {

}
