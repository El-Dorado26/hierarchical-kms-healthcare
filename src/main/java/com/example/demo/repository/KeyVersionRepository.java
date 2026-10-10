package com.example.demo.repository;

import java.util.Optional;


import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.KeyVersion;

public interface KeyVersionRepository
        extends JpaRepository<KeyVersion, Long> {

    Optional<KeyVersion> findByKeyKeyIdAndVersion(
            String keyId,
            int version);

    Optional<KeyVersion> findFirstByKeyKeyIdOrderByVersionDesc(
            String keyId);
}