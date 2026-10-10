package com.example.demo.dto;

public record KeyInfo(
        String keyId,
        String status,
        int version,
        String department
) {
}