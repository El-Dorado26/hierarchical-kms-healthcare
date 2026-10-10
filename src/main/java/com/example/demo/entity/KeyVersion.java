package com.example.demo.entity;

import java.time.Instant;




import jakarta.persistence.*; // Provides JPA annotations(Entity, Table etc) used to map the key version to PostgreSQL

//This class represents data that should be stored in the database, so this becomes key_versions table
@Entity
@Table(
    name = "key_versions",
    uniqueConstraints = {
        @UniqueConstraint(columnNames = {"key_id", "version"})
    }
)
public class KeyVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Many KeyVersion records can belong to one KmsKey
    @ManyToOne(optional = false)
    @JoinColumn(name = "key_id")
    private KmsKey key;

    // Identifies which cryptographic version this record represents
    @Column(nullable = false)
    private int version;

    // It contains the protected DEK produced by KeyWrappingService
    @Column(name = "wrapped_dek", nullable = false, columnDefinition = "TEXT")
    private String wrappedDek;

    // Lifecycle state of this specific version, example Version 1 could be retired and Version 2 Enabled
    // Separate from the lifecycle status of the overall KmsKey
    @Column(nullable = false)
    private String status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public KeyVersion() {
    }

    public Long getId() {
        return id;
    }

    public KmsKey getKey() {
        return key;
    }

    public void setKey(KmsKey key) {
        this.key = key;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public String getWrappedDek() {
        return wrappedDek;
    }

    public void setWrappedDek(String wrappedDek) {
        this.wrappedDek = wrappedDek;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}