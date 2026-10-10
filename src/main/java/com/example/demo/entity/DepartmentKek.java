package com.example.demo.entity;

import java.time.Instant;


import jakarta.persistence.*;

@Entity
@Table(name = "department_keks")
public class DepartmentKek {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(optional = false)
    @JoinColumn(name = "department_id", nullable = false, unique = true)
    private Department department;

    @Column(name = "wrapped_kek", nullable = false, columnDefinition = "TEXT")
    private String wrappedKek;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public DepartmentKek() {
    }

    public Long getId() {
        return id;
    }

    public Department getDepartment() {
        return department;
    }

    public void setDepartment(Department department) {
        this.department = department;
    }

    public String getWrappedKek() {
        return wrappedKek;
    }

    public void setWrappedKek(String wrappedKek) {
        this.wrappedKek = wrappedKek;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}