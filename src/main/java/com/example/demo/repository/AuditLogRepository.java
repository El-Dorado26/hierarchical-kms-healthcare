package com.example.demo.repository;

import java.util.List;



import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.AuditLog;

public interface AuditLogRepository
        extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findAllByOrderByTimestampDesc();
    List<AuditLog> findTop10ByUsernameOrderByTimestampDesc(String username);
}
