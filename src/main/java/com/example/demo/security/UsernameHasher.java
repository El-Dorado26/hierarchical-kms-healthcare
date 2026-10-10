package com.example.demo.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


//new class to look up the hashed user in the database 


@Component
public class UsernameHasher {

    private final byte[] secret;

    public UsernameHasher(
            @Value("${kms.username-hash-secret}") String secret) {

        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    public String hash(String username) throws Exception {

        Mac mac = Mac.getInstance("HmacSHA256");

        SecretKeySpec key = new SecretKeySpec(
                secret,
                "HmacSHA256"
        );

        mac.init(key);

        byte[] hash = mac.doFinal(
                username.getBytes(StandardCharsets.UTF_8)
        );

        return Base64.getEncoder().encodeToString(hash);
    }
}