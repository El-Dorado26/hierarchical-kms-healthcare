package com.example.demo.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;
import com.example.demo.config.MasterKeyConfig;

@Service
public class KeyWrappingService {

    private final SecretKey masterKey;

    public KeyWrappingService(MasterKeyConfig masterKeyConfig) {
        this.masterKey = masterKeyConfig.getMasterKey();
    }

    // Existing behavior, unchanged: always wraps/unwraps under the Master KEK
    public String wrapKey(SecretKey dataKey) throws Exception {
        return wrapKey(dataKey, masterKey);
    }

    public SecretKey unwrapKey(String wrappedKey) throws Exception {
        return unwrapKey(wrappedKey, masterKey);
    }

    // New: wrap/unwrap using ANY given key — a Master KEK or a Department KEK
    public String wrapKey(SecretKey dataKey, SecretKey wrappingKey) throws Exception {

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey, gcmSpec);

        byte[] encryptedKey = cipher.doFinal(dataKey.getEncoded());

        byte[] combined = new byte[iv.length + encryptedKey.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedKey, 0, combined, iv.length, encryptedKey.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public SecretKey unwrapKey(String wrappedKey, SecretKey wrappingKey) throws Exception {

        byte[] combined = Base64.getDecoder().decode(wrappedKey);

        byte[] iv = new byte[12];
        byte[] encryptedDek = new byte[combined.length - 12];
        System.arraycopy(combined, 0, iv, 0, 12);
        System.arraycopy(combined, 12, encryptedDek, 0, encryptedDek.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey, gcmSpec);

        byte[] dekBytes = cipher.doFinal(encryptedDek);

        return new SecretKeySpec(dekBytes, "AES");
    }
}