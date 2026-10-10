package com.example.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.DepartmentKek;

public interface DepartmentKekRepository extends JpaRepository<DepartmentKek, Long> {

    Optional<DepartmentKek> findByDepartmentId(Long departmentId);
}