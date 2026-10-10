package com.example.demo;

import org.springframework.boot.SpringApplication;







import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
/*starting the main application from here, Starts the KMS and automatically discovers and connects
 controllers, services, repositories, and configuration classes.  */
public class AesApplication {

	public static void main(String[] args) {
		String p = System.getenv("KMS_DB_PASSWORD");
		System.out.println("pw length: " + (p == null ? "MISSING" : p.length()));
		SpringApplication.run(AesApplication.class, args);
		
	}

}
