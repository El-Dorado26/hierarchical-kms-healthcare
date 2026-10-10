package com.example.demo.entity;

import jakarta.persistence.*;

@Entity
@Table(
    name = "key_permissions",
    uniqueConstraints = { // Means a user can only have one permission record for a particular key
        @UniqueConstraint(columnNames = {"user_id", "key_id"})
    }
)
public class KeyPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Many permission records can belong to one user
    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id")
    private KmsUser user;

    // This connects the permission to a specific KMS key
    @ManyToOne(optional = false)
    @JoinColumn(name = "key_id")
    private KmsKey key;

    // Controls whether the user can use this particular key for encryption
    @Column(nullable = false)
    private boolean canEncrypt;

    @Column(nullable = false)
    private boolean canDecrypt;

    public KeyPermission() {
    }

    public Long getId() {
        return id;
    }

    public KmsUser getUser() {
        return user;
    }

    public void setUser(KmsUser user) {
        this.user = user;
    }

    public KmsKey getKey() {
        return key;
    }

    public void setKey(KmsKey key) {
        this.key = key;
    }

    public boolean isCanEncrypt() {
        return canEncrypt;
    }

    public void setCanEncrypt(boolean canEncrypt) {
        this.canEncrypt = canEncrypt;
    }

    public boolean isCanDecrypt() {
        return canDecrypt;
    }

    public void setCanDecrypt(boolean canDecrypt) {
        this.canDecrypt = canDecrypt;
    }
}