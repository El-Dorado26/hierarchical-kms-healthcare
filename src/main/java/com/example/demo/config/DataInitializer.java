package com.example.demo.config;

import java.time.Instant;



import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.entity.Department;
import com.example.demo.entity.KmsUser;
import com.example.demo.repository.DepartmentRepository;
import com.example.demo.repository.KmsUserRepository;
import com.example.demo.security.UsernameHasher;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner createInitialUser(
            KmsUserRepository userRepository,
            DepartmentRepository departmentRepository,
            PasswordEncoder passwordEncoder,
            UsernameHasher usernameHasher) {

        return args -> {

            // -----------------------------------------
            // Department: Cardiology
            // -----------------------------------------

            Department Cardiology =
                    departmentRepository
                            .findAll()
                            .stream()
                            .filter(d ->
                                    "Cardiology"
                                            .equals(d.getName()))
                            .findFirst()
                            .orElseGet(() -> {

                                Department department =
                                        new Department();

                                department.setName(
                                        "Cardiology");

                                department.setCreatedAt(
                                        Instant.now());

                                return departmentRepository
                                        .save(department);
                            });

            // -----------------------------------------
            // Department: Radiology
            // -----------------------------------------

            Department Radiology =
                    departmentRepository
                            .findAll()
                            .stream()
                            .filter(d ->
                                    "Radiology"
                                            .equals(d.getName()))
                            .findFirst()
                            .orElseGet(() -> {

                                Department department =
                                        new Department();

                                department.setName(
                                        "Radiology");

                                department.setCreatedAt(
                                        Instant.now());

                                return departmentRepository
                                        .save(department);
                            });

            // -----------------------------------------
            // User 1
            // -----------------------------------------

            KmsUser HospitalStaffUser1 =
                    userRepository
                            .findByUsername("HospitalStaffUser1")
                            .orElseGet(KmsUser::new);

            HospitalStaffUser1.setUsername(
                    "HospitalStaffUser1");
/*
            try {

                HospitalStaffUser1.setUsernameHash(
                        usernameHasher.hash(
                                "HospitalStaffUser1"));

            } catch (Exception e) {

                throw new RuntimeException(
                        "Could not hash username",
                        e);
            }
*/
            System.out.println("========================================");
            System.out.println("Plaintext username lmao: HospitalStaffUser1");

            try {

                String hash = usernameHasher.hash(
                        "HospitalStaffUser1");

                System.out.println("Hashed username: " + hash);

                HospitalStaffUser1.setUsernameHash(hash);

            } catch (Exception e) {

                throw new RuntimeException(
                        "Could not hash username",
                        e);
            }

            System.out.println("========================================");
            HospitalStaffUser1.setPasswordHash(
                    passwordEncoder.encode(
                            "Hospitaluser1"));

            HospitalStaffUser1.setEnabled(true);

            HospitalStaffUser1.setDepartment(
                    Cardiology);

            userRepository.save(
                    HospitalStaffUser1);

            // -----------------------------------------
            // User 2
            // -----------------------------------------

            KmsUser HospitalStaffUser2 =
                    userRepository
                            .findByUsername("HospitalStaffUser2")
                            .orElseGet(KmsUser::new);

            HospitalStaffUser2.setUsername(
                    "HospitalStaffUser2");
/*
            try {

                HospitalStaffUser2.setUsernameHash(
                        usernameHasher.hash(
                                "HospitalStaffUser2"));

            } catch (Exception e) {

                throw new RuntimeException(
                        "Could not hash username",
                        e);
            }
*/
            
            HospitalStaffUser2.setPasswordHash(
                    passwordEncoder.encode(
                            "Hospitaluser2"));

            HospitalStaffUser2.setEnabled(true);

            HospitalStaffUser2.setDepartment(
                    Radiology);

            userRepository.save(
                    HospitalStaffUser2);
        };
    }
}