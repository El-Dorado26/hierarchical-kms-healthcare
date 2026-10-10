package com.example.demo.controller;

import org.springframework.http.ResponseEntity;

import java.util.Map;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.service.KeyService;
import org.springframework.web.bind.annotation.DeleteMapping;
import com.example.demo.dto.KeyInfo;
import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping
    public ResponseEntity<String> createKey() {

        try {
            String keyId = keyService.createKey();

            return ResponseEntity.ok(keyId);

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Failed to create key: " + e.getMessage());
        }
    }
    
    @PostMapping("/{keyId}/disable")
    public ResponseEntity<?> disableKey(
            @PathVariable String keyId) {

        try {

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            keyService.disableKey(keyId, username);

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "status", "DISABLED"
                    )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error", "Forbidden"
                    ));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error", e.getMessage()
                    ));
        }
    }
    @PostMapping("/{keyId}/rotate")
    public ResponseEntity<?> rotateKey(
            @PathVariable String keyId) {

        try {

            String username =
                SecurityContextHolder
                    .getContext()
                    .getAuthentication()
                    .getName();

            int newVersion =
                keyService.rotateKey(keyId, username);

            return ResponseEntity.ok(
                Map.of(
                    "keyId", keyId,
                    "version", newVersion,
                    "status", "ENABLED"
                )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of("error", "Forbidden"));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }
    @PostMapping("/{keyId}/retire")
    public ResponseEntity<?> retireKey(
            @PathVariable String keyId) {

        try {

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            keyService.retireKey(
                    keyId,
                    username);

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "status", "RETIRED"
                    )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error", "Forbidden"
                    ));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error", e.getMessage()
                    ));
        }
    }
    @DeleteMapping("/{keyId}")
    public ResponseEntity<?> deleteKey(
            @PathVariable String keyId) {

        try {

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            keyService.deleteKey(
                    keyId,
                    username);

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "status", "DELETED"
                    )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error", "Forbidden"
                    ));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error", e.getMessage()
                    ));
        }
    }
    
    @GetMapping
    public ResponseEntity<List<KeyInfo>> listKeys() {
        return ResponseEntity.ok(keyService.listMyKeys());
    }
}