package com.example.demo.crypto;

import java.security.SecureRandom;

import java.time.Instant;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.example.demo.entity.Department;
import com.example.demo.entity.DepartmentKek;
import com.example.demo.repository.DepartmentKekRepository;

@Service
public class DepartmentKekService {

    private final KeyWrappingService keyWrappingService;
    private final DepartmentKekRepository departmentKekRepository;

    public DepartmentKekService(
            KeyWrappingService keyWrappingService,
            DepartmentKekRepository departmentKekRepository) {
        this.keyWrappingService = keyWrappingService;
        this.departmentKekRepository = departmentKekRepository;
    }

    /**
     * Returns this department's KEK, unwrapped and ready to use.
     * The first time a department needs one, it's generated fresh
     * and wrapped under the Master KEK before being persisted.
     */
    public SecretKey getOrCreateDepartmentKek(Department department) throws Exception {

        return departmentKekRepository
                .findByDepartmentId(department.getId())
                .map(this::unwrap)
                .orElseGet(() -> {
                    try {
                        return createDepartmentKek(department);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private SecretKey unwrap(DepartmentKek departmentKek) {
        try {
            return keyWrappingService.unwrapKey(departmentKek.getWrappedKek());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey createDepartmentKek(Department department) throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, new SecureRandom());
        SecretKey rawKek = keyGenerator.generateKey();

        String wrapped = keyWrappingService.wrapKey(rawKek);

        DepartmentKek entity = new DepartmentKek();
        entity.setDepartment(department);
        entity.setWrappedKek(wrapped);
        entity.setCreatedAt(Instant.now());

        departmentKekRepository.save(entity);

        return rawKek;
    }
}