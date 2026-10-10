package com.example.demo.config;

import java.util.Base64;
// Provides Base64 decoding so the master key string can be converted back into raw key bytes.
//As the master key is stored as a Base64 string in KMS_MASTER_KEY.


import javax.crypto.SecretKey; //Represents the symmetric master/KEK key used to protect DEKs.
import javax.crypto.spec.SecretKeySpec;
//Converts the decoded master-key bytes into a SecretKey object usable by Java's AES cryptographic APIs.

import org.springframework.beans.factory.annotation.Value;
//Allows Spring to inject the configured master-key value into this class.

import org.springframework.context.annotation.Configuration;
//Marks this class as a Spring configuration component.

@Configuration // Tells Spring to Create and manage this class as part of the application.
public class MasterKeyConfig {

    private final SecretKey masterKey;
    // master/KEK used to wrap and unwrap DEKs.

 // Loads the master/KEK value provided through the application's external configuration.
    public MasterKeyConfig(@Value("${kms.master-key}") String masterKey) {

    	// Decodes the Base64-encoded master/KEK into its raw cryptographic bytes.
        byte[] keyBytes = Base64.getDecoder().decode(masterKey);

        //Now masterKey is an object that Java's Cipher API can use.(this.masterKey)
        //Converts the raw master-key bytes into an AES SecretKey used to wrap and unwrap DEKs.
        this.masterKey = new SecretKeySpec(keyBytes, "AES");
    }

    //Provides the master/KEK to the key-wrapping component(example KeyWrappingService) when cryptographic key protection is required.
    public SecretKey getMasterKey() {
        return masterKey;
    }
}