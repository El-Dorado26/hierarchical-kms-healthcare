package com.example.demo.repository;

import java.util.Optional;



import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.KmsUser;

public interface KmsUserRepository extends JpaRepository<KmsUser, Long> {

    Optional<KmsUser> findByUsername(String username);
    Optional<KmsUser> findByUsernameHash(String usernameHash);//now can verify it with the hashsed username
}

