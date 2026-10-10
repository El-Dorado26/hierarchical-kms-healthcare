package com.example.demo.controller;

import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.crypto.AesService;
import com.example.demo.service.AuditService;
import com.example.demo.service.KeyService;

//new import for the client-end encryption 
import org.springframework.web.bind.annotation.GetMapping;
@RestController
@RequestMapping("/api/crypto")
public class CryptoController {

	//private final AesService aesService;
    private final KeyService keyService;
    private final AuditService auditService;

    public CryptoController(
    	//	AesService aesService,
            KeyService keyService,
            AuditService auditService) {

    	//this.aesService = aesService;
        this.keyService = keyService;
        this.auditService = auditService;
    }

    /*
     * The KMS no longer receives plaintext.
     *
     * This endpoint:
     * 1. Authenticates the user through Spring Security.
     * 2. Checks whether the user can encrypt with the requested key.
     * 3. Gets the authorized key material.
     * 4. Sends the key material to the client.
     *
     * The React application performs AES-GCM encryption locally.
     */
    
    @PostMapping("/encrypt")
    public ResponseEntity<?> encrypt(
            @RequestBody Map<String, String> body) {

        try {

            String keyId = body.get("keyId");

            if (keyId == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "error",
                                "keyId is required"
                        ));
            }

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            // Authorization happens before the key is released
            String keyMaterial =
                    keyService.getKeyMaterialForEncryption(
                            keyId,
                            username);

            // Get the currently active key version
            int version =
                    keyService.getCurrentVersion(keyId);

            // Record that the authorized encryption key was released
            auditService.log(
                    username,
                    "ENCRYPT_KEY_RELEASE",
                    keyId,
                    "SUCCESS",
                    "Encryption key released for client-side encryption using key version " + version
            );

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "version", version,
                            "keyMaterial", keyMaterial
                    )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error",
                            "Forbidden"
                    ));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error",
                            e.getMessage()
                    ));
        }
    }
    
    /*
    @PostMapping("/encrypt")
    public ResponseEntity<?> encrypt(
            @RequestBody Map<String, String> body) {

        try {

            String keyId = body.get("keyId");
            String text = body.get("text");
            
            System.out.println("haha the plaintext i can see: " + text);

            if (keyId == null || text == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "error",
                                "keyId and text are required"
                        ));
            }

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            // Authorization happens before the key is unwrapped
            SecretKey key =
                    keyService.getKeyForOperation(
                            keyId,
                            username,
                            "ENCRYPT");

            // Get the currently active key version
            int version =
                    keyService.getCurrentVersion(keyId);

            // Perform AES-GCM encryption
            String ciphertext =
                    aesService.encrypt(text, key);

            // Record successful encryption
            auditService.log(
                    username,
                    "ENCRYPT",
                    keyId,
                    "SUCCESS",
                    "Data encrypted using key version " + version
            );

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "version", version,
                            "ciphertext", ciphertext
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
*/
    /*
     * The KMS no longer receives ciphertext to decrypt.
     *
     * This endpoint:
     * 1. Authenticates the user.
     * 2. Checks whether the user can decrypt the requested key version.
     * 3. Gets the authorized key material.
     * 4. Sends the key material to the client.
     *
     * The React application performs AES-GCM decryption locally.
     */
    
    @PostMapping("/decrypt")
    public ResponseEntity<?> decrypt(
            @RequestBody Map<String, Object> body) {

        try {

            String keyId =
                    (String) body.get("keyId");

            Integer version =
                    (Integer) body.get("version");

            if (keyId == null ||
                    version == null) {

                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "error",
                                "keyId and version are required"
                        ));
            }

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            // Authorization happens before the key is released
            String keyMaterial =
                    keyService.getKeyMaterialForDecryption(
                            keyId,
                            version,
                            username);

            // Record that the authorized decryption key was released
            auditService.log(
                    username,
                    "DECRYPT_KEY_RELEASE",
                    keyId,
                    "SUCCESS",
                    "Decryption key released for client-side decryption using key version " + version
            );

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "version", version,
                            "keyMaterial", keyMaterial
                    )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error",
                            "Forbidden"
                    ));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error",
                            e.getMessage()
                    ));
        }
    }
    
   /*
    @PostMapping("/decrypt")
    public ResponseEntity<?> decrypt(
            @RequestBody Map<String, Object> body) {

        try {

            String keyId =
                    (String) body.get("keyId");

            Integer version =
                    (Integer) body.get("version");

            String ciphertext =
                    (String) body.get("ciphertext");

            if (keyId == null ||
                    version == null ||
                    ciphertext == null) {

                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "error",
                                "keyId, version and ciphertext are required"
                        ));
            }

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            // Authorization happens before the key is unwrapped
            SecretKey key =
                    keyService.getKeyForVersion(
                            keyId,
                            version,
                            username);

            // Perform AES-GCM decryption
            String plaintext =
                    aesService.decrypt(
                            ciphertext,
                            key);

            // Record successful decryption
            auditService.log(
                    username,
                    "DECRYPT",
                    keyId,
                    "SUCCESS",
                    "Data decrypted using key version " + version
            );

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "version", version,
                            "plaintext", plaintext
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
    */
    //new method for the client-end encryption 
    
    @GetMapping("/auth-check")
    public ResponseEntity<?> authCheck(){
    	String username = SecurityContextHolder.getContext().getAuthentication().getName();
    	
    	return ResponseEntity.ok(Map.of("username", username));
    }
    
    //new boz addition
    @PostMapping("/new-encryption-key")
    public ResponseEntity<?> createEncryptionKey() {

        try {

            String username =
                    SecurityContextHolder
                            .getContext()
                            .getAuthentication()
                            .getName();

            String result =
                    keyService.createKeyAndGetMaterial();

            String[] parts = result.split("\\|", 3);

            String keyId = parts[0];
            int version = Integer.parseInt(parts[1]);
            String keyMaterial = parts[2];

            auditService.log(
                    username,
                    "AUTO_KEY_CREATE",
                    keyId,
                    "SUCCESS",
                    "New encryption key automatically generated and released for client-side file encryption using version " + version
            );

            return ResponseEntity.ok(
                    Map.of(
                            "keyId", keyId,
                            "version", version,
                            "keyMaterial", keyMaterial
                    )
            );

        } catch (SecurityException e) {

            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error",
                            "Forbidden"
                    ));

        } catch (Exception e) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error",
                            e.getMessage()
                    ));
        }
    }
    
}