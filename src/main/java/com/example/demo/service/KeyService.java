package com.example.demo.service;

import java.time.Instant; //brings in classes for timestamps\








import java.util.UUID; //brings in classes for unique IDs

import javax.crypto.KeyGenerator; //brings in classes for cryptographic key generation
import javax.crypto.SecretKey;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.example.demo.crypto.KeyWrappingService;
import com.example.demo.entity.Department;
import com.example.demo.entity.KeyPermission;
import com.example.demo.entity.KeyVersion;
import com.example.demo.entity.KmsKey;
import com.example.demo.entity.KmsUser;
import com.example.demo.repository.KeyPermissionRepository;
import com.example.demo.repository.KeyVersionRepository;
import com.example.demo.repository.KmsKeyRepository;
import com.example.demo.repository.KmsUserRepository;
import org.springframework.transaction.annotation.Transactional;
import com.example.demo.crypto.DepartmentKekService;
import com.example.demo.dto.KeyInfo;
import java.util.List;
//new imports for encrypting on the client side
import java.util.Base64;

@Service
public class KeyService {

    private final KeyWrappingService keyWrappingService;
    private final KmsKeyRepository kmsKeyRepository;
    private final KeyVersionRepository keyVersionRepository;
    private final KmsUserRepository kmsUserRepository;
    private final KeyPermissionRepository keyPermissionRepository;
    private final AuditService auditService;

 // new field + constructor param
 private final DepartmentKekService departmentKekService;


 public KeyService(
	        KeyWrappingService keyWrappingService,
	        DepartmentKekService departmentKekService,
	        KmsKeyRepository kmsKeyRepository,
	        KeyVersionRepository keyVersionRepository,
	        KmsUserRepository kmsUserRepository,
	        KeyPermissionRepository keyPermissionRepository,
	        AuditService auditService) {
	    this.keyWrappingService = keyWrappingService;
	    this.departmentKekService = departmentKekService;
	    this.kmsKeyRepository = kmsKeyRepository;
	    this.keyVersionRepository = keyVersionRepository;
	    this.kmsUserRepository = kmsUserRepository;
	    this.keyPermissionRepository = keyPermissionRepository;
	    this.auditService = auditService;
	}
 //This is where a new logical key is created.
 public String createKey() throws Exception {

	 //get current user and returns the username of whoever is logged in.
//I used "SecurityContextHolder" to figure out which user is creating the key, so I could tie the key to their department and permissions.
	    String username = SecurityContextHolder.getContext().getAuthentication().getName(); 

	    //find user entity
	    KmsUser user = kmsUserRepository.findByUsername(username)
	            .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

	    //Get department KEK, as each department has one.
	    Department department = user.getDepartment();
	    SecretKey departmentKek = departmentKekService.getOrCreateDepartmentKek(department);

	    //Creates a new 256-bit AES Data Encryption Key.
	    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	    keyGenerator.init(256);
	    SecretKey dek = keyGenerator.generateKey();

	    //DEK is encrypted under the department KEK.
	    String keyId = UUID.randomUUID().toString();
	    String wrappedDek = keyWrappingService.wrapKey(dek, departmentKek);

	    //Creates a logical key record in DB
	    KmsKey kmsKey = new KmsKey();
	    kmsKey.setKeyId(keyId);
	    kmsKey.setAlgorithm("AES-256-GCM");
	    kmsKey.setPurpose("DATA_ENCRYPTION");
	    kmsKey.setStatus("ENABLED");
	    kmsKey.setDepartment(department);
	    kmsKey.setCreatedBy(user);
	    kmsKey.setCreatedAt(Instant.now());

	    kmsKeyRepository.save(kmsKey);
	    
	    //First version of the key is stored.
	    KeyVersion version = new KeyVersion();
	    version.setKey(kmsKey);
	    version.setVersion(1);
	    version.setWrappedDek(wrappedDek);
	    version.setStatus("ENABLED");
	    version.setCreatedAt(Instant.now());
	    keyVersionRepository.save(version);

	    //grant permissions 
	    KeyPermission permission = new KeyPermission();
	    permission.setUser(user);
	    permission.setKey(kmsKey);
	    permission.setCanEncrypt(true);
	    permission.setCanDecrypt(true);
	    keyPermissionRepository.save(permission);

	    
	    auditService.log(username, "KEY_CREATED", keyId, "SUCCESS",
	            "AES-256-GCM key created under department " + department.getName());

	    return keyId; //The unique identifier for the new key.
	}
 
/*Checks if user has permission (ENCRYPT or DECRYPT).
 Then finds the logical key and latest version. Then it unwraps DEK using department KEK, and
 lastly return the usable secret key.
 */
    public SecretKey getKeyForOperation(
            String keyId,
            String username,
            String operation) throws Exception {

        // --------------------------------------------------
        // 1. Authorization FIRST
        // --------------------------------------------------

    	KeyPermission permission;

    	try {

    	    permission =
    	            keyPermissionRepository
    	                    .findByUserUsernameAndKeyKeyId(
    	                            username,
    	                            keyId)
    	                    .orElseThrow(() ->
    	                            new SecurityException(
    	                                    "Access denied"));

    	} catch (SecurityException e) {

    	    auditService.log(
    	            username,
    	            operation,
    	            keyId,
    	            "DENIED",
    	            "User does not have permission"
    	    );

    	    throw e;
    	}

        boolean allowed;

        if ("ENCRYPT".equals(operation)) {
            allowed = permission.isCanEncrypt();

        } else if ("DECRYPT".equals(operation)) {
            allowed = permission.isCanDecrypt();

        } else {
            throw new IllegalArgumentException(
                    "Unsupported operation");
        }

        if (!allowed) {

            auditService.log(
                    username,
                    operation,
                    keyId,
                    "DENIED",
                    "Operation not permitted"
            );

            throw new SecurityException(
                    "Access denied");
        }

        // --------------------------------------------------
        // 2. Find the logical key
        // --------------------------------------------------

        KmsKey kmsKey =
                kmsKeyRepository
                        .findByKeyId(keyId)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Key not found"));

        if (!"ENABLED".equals(kmsKey.getStatus())) {
            throw new IllegalStateException(
                    "Key is not enabled");
        }

        // --------------------------------------------------
        // 3. Find the newest key version
        // --------------------------------------------------

        KeyVersion currentVersion =
                keyVersionRepository
                        .findFirstByKeyKeyIdOrderByVersionDesc(
                                keyId)
                        .orElseThrow(() ->
                                new IllegalStateException(
                                        "No key version found"));

        // For now, only use an enabled version
        if (!"ENABLED".equals(currentVersion.getStatus())) {
            throw new IllegalStateException(
                    "Current key version is not enabled");
        }

        // --------------------------------------------------
        // 4. Unwrap the DEK
        // --------------------------------------------------

        SecretKey departmentKek = departmentKekService.getOrCreateDepartmentKek(kmsKey.getDepartment());
        return keyWrappingService.unwrapKey(currentVersion.getWrappedDek(), departmentKek);
    }
    /*First it ensures user has permission. Then it retires the old version (RETIRED).
     Generates new DEK, wraps it, saves as new version. Logs the rotation and then returns the new version.
*/
    @Transactional //Tells Spring to run this method inside a database transaction.
    public int rotateKey(
            String keyId,
            String username) throws Exception {

        // Check that the user has permission
        KeyPermission permission =
            keyPermissionRepository
                .findByUserUsernameAndKeyKeyId(
                    username,
                    keyId)
                .orElseThrow(() ->
                    new SecurityException("Access denied"));

        if (!permission.isCanEncrypt()) {
            throw new SecurityException("Access denied");
        }

        KmsKey kmsKey =
            kmsKeyRepository.findByKeyId(keyId)
                .orElseThrow(() ->
                    new IllegalArgumentException("Key not found"));

        if (!"ENABLED".equals(kmsKey.getStatus())) {
            throw new IllegalStateException(
                "Key is not enabled");
        }

        KeyVersion current =
            keyVersionRepository
                .findFirstByKeyKeyIdOrderByVersionDesc(
                    keyId)
                .orElseThrow(() ->
                    new IllegalStateException(
                        "No key version found"));

        // Retire the old version
        current.setStatus("RETIRED");
        keyVersionRepository.save(current);

        // Generate new DEK
     
        SecretKey departmentKek = departmentKekService.getOrCreateDepartmentKek(kmsKey.getDepartment());

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey newDek = keyGenerator.generateKey();

        String wrappedDek = keyWrappingService.wrapKey(newDek, departmentKek);

        // Create new version
        KeyVersion newVersion =
            new KeyVersion();

        newVersion.setKey(kmsKey);
        newVersion.setVersion(
            current.getVersion() + 1);
        newVersion.setWrappedDek(wrappedDek);
        newVersion.setStatus("ENABLED");
        newVersion.setCreatedAt(Instant.now());

        keyVersionRepository.save(newVersion);
        
        auditService.log(
                username,
                "ROTATE",
                keyId,
                "SUCCESS",
                "Created key version " + newVersion.getVersion()
        );

        return newVersion.getVersion();
    }
    
    //First it checks permission then marks the logical key as (DISABLED) then logs this action.
    public void disableKey(
            String keyId,
            String username) {

        // Check whether the user has permission for this key
        KeyPermission permission =
                keyPermissionRepository
                        .findByUserUsernameAndKeyKeyId(
                                username,
                                keyId)
                        .orElseThrow(() ->
                                new SecurityException(
                                        "Access denied"));

        //require at least one key-management permission.
        if (!permission.isCanEncrypt()
                && !permission.isCanDecrypt()) {
            throw new SecurityException(
                    "Access denied");
        }

        // Find the logical key
        KmsKey kmsKey =
                kmsKeyRepository
                        .findByKeyId(keyId)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Key not found"));

        // Prevent disabling an already deleted key
        if ("DELETED".equals(kmsKey.getStatus())) {
            throw new IllegalStateException(
                    "Key is already deleted");
        }

        // Disable the logical key
        kmsKey.setStatus("DISABLED");
        kmsKeyRepository.save(kmsKey);
        
        auditService.log(
                username,
                "DISABLE",
                keyId,
                "SUCCESS",
                "Key disabled"
        );
        
    }
    //Finds latest enabled version. This returns its version number.
    public int getCurrentVersion(String keyId) {

        return keyVersionRepository
                .findFirstByKeyKeyIdOrderByVersionDesc(keyId)
                .filter(version -> "ENABLED".equals(version.getStatus()))
                .orElseThrow(() ->
                        new IllegalStateException(
                                "No enabled key version found"))
                .getVersion();
    }
    /*Checks permission (must allow decrypt), then it finds the SPECIFIC version, ensures it ain't 
     destroyed. Then unwraps the DEK with department KEK, lastly it returns that usable key. 
      */

    public SecretKey getKeyForVersion(
            String keyId,
            int version,
            String username) throws Exception {

        // Authorization first
    	KeyPermission permission;

    	try {

    	    permission =
    	            keyPermissionRepository
    	                    .findByUserUsernameAndKeyKeyId(
    	                            username,
    	                            keyId)
    	                    .orElseThrow(() ->
    	                            new SecurityException(
    	                                    "Access denied"));

    	} catch (SecurityException e) {

    	    auditService.log(
    	            username,
    	            "DECRYPT",
    	            keyId,
    	            "DENIED",
    	            "User does not have permission"
    	    );

    	    throw e;
    	}

    	if (!permission.isCanDecrypt()) {

    	    auditService.log(
    	            username,
    	            "DECRYPT",
    	            keyId,
    	            "DENIED",
    	            "Decryption not permitted"
    	    );

    	    throw new SecurityException(
    	            "Access denied");
    	}

        if (!permission.isCanDecrypt()) {
            throw new SecurityException(
                    "Access denied");
        }

        // Find the logical key
        KmsKey kmsKey =
                kmsKeyRepository
                        .findByKeyId(keyId)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Key not found"));

        // Find the requested historical version
        KeyVersion keyVersion =
                keyVersionRepository
                        .findByKeyKeyIdAndVersion(
                                keyId,
                                version)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Key version not found"));

        // Don't allow versions that have been destroyed/deleted
        if ("DESTROYED".equals(keyVersion.getStatus())) {
            throw new IllegalStateException(
                    "Key version has been destroyed");
        }

        // Unwrap the specific DEK
        SecretKey departmentKek = departmentKekService.getOrCreateDepartmentKek(kmsKey.getDepartment());
        return keyWrappingService.unwrapKey(keyVersion.getWrappedDek(), departmentKek);
    }
 //Marks logical key as (RETIRED) to prevent its future use and then logs this action.   
    public void retireKey(
            String keyId,
            String username) {

        // Check authorization first
        KeyPermission permission =
                keyPermissionRepository
                        .findByUserUsernameAndKeyKeyId(
                                username,
                                keyId)
                        .orElseThrow(() ->
                                new SecurityException(
                                        "Access denied"));

        if (!permission.isCanEncrypt()
                && !permission.isCanDecrypt()) {
            throw new SecurityException(
                    "Access denied");
        }

        // Find the logical key
        KmsKey kmsKey =
                kmsKeyRepository
                        .findByKeyId(keyId)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Key not found"));

        if ("DELETED".equals(kmsKey.getStatus())) {
            throw new IllegalStateException(
                    "Key is already deleted");
        }

        if ("RETIRED".equals(kmsKey.getStatus())) {
            throw new IllegalStateException(
                    "Key is already retired");
        }

        // A retired key cannot be used for new operations
        kmsKey.setStatus("RETIRED");

        kmsKeyRepository.save(kmsKey);
        
        auditService.log(
                username,
                "RETIRE",
                keyId,
                "SUCCESS",
                "Key retired"
        );
    }
    //Requires key to be retired first to delete the key
    @Transactional
    public void deleteKey(
            String keyId,
            String username) {

        // Check authorization first
        KeyPermission permission =
                keyPermissionRepository
                        .findByUserUsernameAndKeyKeyId(
                                username,
                                keyId)
                        .orElseThrow(() ->
                                new SecurityException(
                                        "Access denied"));

        if (!permission.isCanEncrypt()
                && !permission.isCanDecrypt()) {
            throw new SecurityException(
                    "Access denied");
        }

        // Find the key
        KmsKey kmsKey =
                kmsKeyRepository
                        .findByKeyId(keyId)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Key not found"));

        // Require the key to be retired before deletion
        if (!"RETIRED".equals(kmsKey.getStatus())) {
            throw new IllegalStateException(
                    "Key must be retired before deletion");
        }

        /*
         * Delete permissions first because they reference
         * the logical key.
         */
        
        auditService.log(
                username,
                "DELETE",
                keyId,
                "SUCCESS",
                "Key deleted"
        );
        keyPermissionRepository.deleteByKeyKeyId(keyId);

        /*
         * KmsKey has cascade + orphanRemoval for its
         * KeyVersion records, so deleting the logical
         * key also removes its key versions.
         *
         * This removes the wrapped DEKs from PostgreSQL.
         */
        kmsKeyRepository.delete(kmsKey);
    }
    public List<KeyInfo> listMyKeys() {

        String username =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getName();

        return keyPermissionRepository
                .findByUserUsername(username)
                .stream()
                .map(permission -> {

                    KmsKey key = permission.getKey();

                    int version = keyVersionRepository
                            .findFirstByKeyKeyIdOrderByVersionDesc(key.getKeyId())
                            .map(KeyVersion::getVersion)
                            .orElse(0);

                    return new KeyInfo(
                            key.getKeyId(),
                            key.getStatus(),
                            version,
                            key.getDepartment().getName()
                    );
                })
                .toList();
    }
    
    //new methods for client side encryption 
    public String getKeyMaterialForEncryption (String keyId, String username)
    		throws Exception {
    	//checking if the user is allowed to encrypt
    	SecretKey key = getKeyForOperation(keyId, username, "ENCRYPT");
    	
    	//Converting the key into raw bytes 
    	byte[] keyBytes = key.getEncoded();
    	
    	//convertin the bytes to base64 so React can receive them.
    	return Base64.getEncoder().encodeToString(keyBytes);
    	
    }
    
    public String getKeyMaterialForDecryption (String keyId, int version, String username)
    		throws Exception {
    	//checking if the user is allowed to decrypt
    	SecretKey key = getKeyForVersion(keyId, version, username);
    	
    	//Converting the AES into raw bytes 
    	byte[] keyBytes = key.getEncoded();
    	
    	//convertin the bytes to base64 so React can receive them.
    	return Base64.getEncoder().encodeToString(keyBytes);
    	
    }
    //new boz addition
    
    public String createKeyAndGetMaterial() throws Exception {

        // Create a completely new key for this encryption request
        String keyId = createKey();

        // Get the currently active version
        int version = getCurrentVersion(keyId);

        // Get the authenticated user
        String username =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getName();

        // Get the newly created key material
        String keyMaterial =
                getKeyMaterialForEncryption(
                        keyId,
                        username);

        return keyId + "|" + version + "|" + keyMaterial;
    }
    
}