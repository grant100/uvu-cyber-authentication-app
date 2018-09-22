package edu.uvu.cybersecurity.domains;

import javax.persistence.*;

import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Table(name = "authority")
public class Authority {

    @Column(name = "authority_role")
    private String role;

    @Column(name = "authority_key")
    private Long key;

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "authority_id")
    private Long id;

    public Authority(){}

    public Authority(String role) {
        this.role = role;
    }

    public Authority(String role, Long key) {
        this.role = role;
        this.key = key;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public Long getKey() {
        return key;
    }

    public void setKey(Long key) {
        this.key = key;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
}
