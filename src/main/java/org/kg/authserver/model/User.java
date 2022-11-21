package org.kg.authserver.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder(setterPrefix = "with")
@EqualsAndHashCode
public class User {

    @Id
    @Getter
    @GeneratedValue
    private UUID id;

    @Getter
    @NotBlank
    @Size(max = 32)
    private String username;

    @Getter
    @NotBlank
    @Size(max = 128)
    private String password;

    @Getter
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
               inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    private Set<Role> roles = new HashSet<>();

    public void addRole(final Role role) {
        this.roles.add(role);
    }
}
