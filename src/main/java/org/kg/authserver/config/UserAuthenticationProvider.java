package org.kg.authserver.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.kg.authserver.model.User;
import org.kg.authserver.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.CharBuffer;
import java.util.stream.Collectors;


/**
 * Provider which will validate the Authentication object present in the SecurityContext.
 * The only acceptable Authentication object is the UsernamePasswordAuthenticationToken which comes from the
 * UserAuthenticationConverter. Then, from the username and password present in the Authentication object, I
 * validate the information against the database.
 * If the username and password don't match with the data present in the database, null is returned as the
 * Authentication object in the SecurityContext.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String username = authentication.getName();
        final String password = authentication.getCredentials()
                                              .toString();

        final User user = userRepository.findByUsername(username)
                                        .orElse(null);
        if (user == null) {
            return UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        }

        if (passwordEncoder.matches(CharBuffer.wrap(password), user.getPassword())) {
            return UsernamePasswordAuthenticationToken.authenticated(username, password, user.getRoles()
                                                                                             .stream()
                                                                                             .map(role -> new SimpleGrantedAuthority(
                                                                                                     role.getName()
                                                                                                         .name()))
                                                                                             .collect(
                                                                                                     Collectors.toSet()));
        }
        return UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        //return null;
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
