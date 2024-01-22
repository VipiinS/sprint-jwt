package com.vipin.JWTdemo.repository;

import com.vipin.JWTdemo.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserInfo,Long> {
    UserInfo findByUsername(String username);

    boolean existsByUsername(String username);
}
