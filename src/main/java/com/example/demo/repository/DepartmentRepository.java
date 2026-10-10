package com.example.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.Department;

public interface DepartmentRepository
        extends JpaRepository<Department, Long> {
	Optional<Department> findByName(String name);

}