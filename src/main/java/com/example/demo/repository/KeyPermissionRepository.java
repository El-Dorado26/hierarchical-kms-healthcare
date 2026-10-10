package com.example.demo.repository;

import java.util.List;
import java.util.Optional;



import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.KeyPermission;

public interface KeyPermissionRepository
        extends JpaRepository<KeyPermission, Long> {

    Optional<KeyPermission> findByUserUsernameAndKeyKeyId(
            String username,
            String keyId);
    
    List<KeyPermission> findByUserUsername(String username);

    void deleteByKeyKeyId(String keyId);
}