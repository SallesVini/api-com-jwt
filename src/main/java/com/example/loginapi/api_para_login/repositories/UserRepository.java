package com.example.loginapi.api_para_login.repositories;

import com.example.loginapi.api_para_login.entities.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByEmail(String email);
}
