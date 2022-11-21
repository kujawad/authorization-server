package org.kg.authserver.controllers;

import lombok.AllArgsConstructor;
import org.kg.authserver.model.Role;
import org.kg.authserver.model.RoleType;
import org.kg.authserver.model.User;
import org.kg.authserver.payload.request.SignupRequest;
import org.kg.authserver.repository.RoleRepository;
import org.kg.authserver.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import javax.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {
    AuthenticationManager authenticationManager;
    UserRepository userRepository;
    RoleRepository roleRepository;
    PasswordEncoder encoder;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest()
                                 .body(Map.of("message", "Error: Username is already taken!"));
        }

        saveUser(signUpRequest);
        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    @Transactional
    void saveUser(final SignupRequest signUpRequest) {
        final Role userRole = roleRepository.findByName(RoleType.ROLE_USER)
                                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        final User user = User.builder()
                              .withUsername(signUpRequest.getUsername())
                              .withPassword(encoder.encode(signUpRequest.getPassword()))
                              .withRoles(Set.of(userRole))
                              .build();
        userRepository.save(user);

    }

    @GetMapping("/all")
    public ResponseEntity<?> getAll() {
        return ResponseEntity.ok(List.of(userRepository.findAll()));
    }
}
