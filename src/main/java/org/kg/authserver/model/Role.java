package org.kg.authserver.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;

import javax.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "roles")
@EqualsAndHashCode
public class Role {

    @Id
    @Getter
    @GeneratedValue
    private UUID id;

    @Getter
    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private RoleType name;
}