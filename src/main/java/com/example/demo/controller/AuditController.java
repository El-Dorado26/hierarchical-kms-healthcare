package com.example.demo.controller;

import java.util.List;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.entity.AuditLog;
import com.example.demo.repository.AuditLogRepository;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    public AuditController(
            AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping
    public ResponseEntity<List<AuditLog>> getAuditLogs() {
        return ResponseEntity.ok(
                auditLogRepository
                        .findAllByOrderByTimestampDesc()
        );
    }
    
    @GetMapping("/security-tests")
    public ResponseEntity<List<AuditLog>> getSecurityTestResults() {
        return ResponseEntity.ok(
                auditLogRepository.findTop10ByUsernameOrderByTimestampDesc("SYSTEM")
        );
    }
    
}