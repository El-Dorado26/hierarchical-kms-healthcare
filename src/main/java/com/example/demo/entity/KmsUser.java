package com.example.demo.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "kms_users")
public class KmsUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // username apps internal identity 
    // usernameHash is now a protected database representation
    @Column(nullable = false, unique = true)
    private String username;

    @Column(name = "username_hash", nullable = false, unique = true)
    private String usernameHash;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private boolean enabled = true;

    // Each KMS user belongs to one department
    @ManyToOne(optional = false)
    @JoinColumn(name = "department_id", nullable = false)
    private Department department;

    public KmsUser() {
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsernameHash() {
        return usernameHash;
    }

    public void setUsernameHash(String usernameHash) {
        this.usernameHash = usernameHash;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Department getDepartment() {
        return department;
    }

    public void setDepartment(Department department) {
        this.department = department;
    }
}