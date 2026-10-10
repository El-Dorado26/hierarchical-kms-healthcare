package com.example.demo.crypto;

import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Service;

@Service
public class AesService { //Performs AES 256-GCM encryption and decryption using a DEK supplied by the KMS

    private static final int IV_LENGTH = 12; // uses a fresh 96 bit IV for every AES-GCM encryption.
    private static final int TAG_LENGTH = 128; // Uses a 128 bit authentication tag to detect(by GCM) ciphertext tampering.

    public String encrypt( //encrypts plaintext using the DEK supplied by the KMS
            String plaintext,
            SecretKey key) throws Exception {

        // Generate a fresh IV for every encryption
        byte[] iv = new byte[IV_LENGTH];

        SecureRandom secureRandom =
                new SecureRandom();

        secureRandom.nextBytes(iv); //fills the IV with random bytes

        //AES-GCM cryptographic operation
        Cipher cipher =
                Cipher.getInstance("AES/GCM/NoPadding");

        //GCM parameters
        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(TAG_LENGTH, iv);

     // Initialize AES-GCM encryption with the managed DEK and fresh IV
        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                gcmSpec
        );

        //plaintext is converted into bytes and then AES-GCM encrypts that and produces ciphertext + authentication tag
        byte[] ciphertext =
                cipher.doFinal(
                        plaintext.getBytes(StandardCharsets.UTF_8)
                );

        // Store IV + ciphertext together
        byte[] combined =
                new byte[iv.length + ciphertext.length];

        // putting the IV first and then the ciphertext 
        // [ 12-byte IV ][ ciphertext + GCM tag ]
        System.arraycopy(
                iv,
                0,
                combined,
                0,
                iv.length
        );

        System.arraycopy(
                ciphertext,
                0,
                combined,
                iv.length,
                ciphertext.length
        );
        
        System.out.println("Server encryption called");

        return Base64.getEncoder()
                .encodeToString(combined);// convert the binary data into a string to feed it to the REST API
    }
    // Decrypts previously encrypted data using the corresponding DEK
    // receives the base64 ciphertext and the DEK(given by KeyService.java)
    public String decrypt(
            String encodedCiphertext,
            SecretKey key) throws Exception {

        byte[] combined =
                Base64.getDecoder()
                        .decode(encodedCiphertext);

        if (combined.length < IV_LENGTH) {
            throw new IllegalArgumentException(
                    "Invalid ciphertext");
        }

        byte[] iv = new byte[IV_LENGTH];//Extract the original IV from the beginning of the encrypted data

        //Extract ciphertext
        byte[] ciphertext =
                new byte[combined.length - IV_LENGTH];

        System.arraycopy(
                combined,
                0,
                iv,
                0,
                IV_LENGTH
        );

        System.arraycopy(
                combined,
                IV_LENGTH,
                ciphertext,
                0,
                ciphertext.length
        );

        Cipher cipher =
                Cipher.getInstance("AES/GCM/NoPadding");

        //Recreate the GCM parameters using the same 128 bit tag size and the IV.
        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(TAG_LENGTH, iv);

        // Decrypt the ciphertext and verify its authentication tag
        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                gcmSpec
        );

        byte[] plaintext =
                cipher.doFinal(ciphertext);

        return new String(
                plaintext,
                StandardCharsets.UTF_8
        );
    }
}