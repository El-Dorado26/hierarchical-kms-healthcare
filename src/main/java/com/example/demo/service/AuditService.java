package com.example.demo.service;

import java.time.Instant;

import org.springframework.stereotype.Service;

import com.example.demo.entity.AuditLog;
import com.example.demo.repository.AuditLogRepository;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void log(
            String username,
            String operation,
            String keyId,
            String result,
            String details) {

        AuditLog log = new AuditLog();

        log.setTimestamp(Instant.now());
        log.setUsername(username);
        log.setOperation(operation);
        log.setKeyId(keyId);
        log.setResult(result);
        log.setDetails(details);

        auditLogRepository.save(log);
    }
}
