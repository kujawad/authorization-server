package org.kg.authserver.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.Optional;

@Slf4j
@Configuration
@AllArgsConstructor
public class AuthorizationServerConfig {

    private final ApplicationProperties applicationProperties;
    private final PasswordEncoder encoder;

    /**
     * First OAuth2 security filter configuration with custom authentication entry point
     * on failed authentication.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        return http.build();
    }

    /**
     * Configuration of the OAuth2 client.
     * Stores RegisteredClient in database via JdbcTemplate.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        final RegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        applicationProperties.getClients()
                             .forEach(client -> {
                                 Optional.ofNullable(repository.findByClientId(client.getClientId()))
                                         .ifPresentOrElse(ignore -> {
                                             log.info("Client with identifier '{}' already exists!",
                                                      client.getClientId());
                                         }, () -> {
                                             log.info("Saving client with identifier '{}' to database.",
                                                      client.getClientId());
                                             repository.save(client.asRegisteredClient(encoder));
                                         });
                             });
        return repository;
    }

    /**
     * Acceptable URL of the authorization server.
     */
    @Bean
    public ProviderSettings authorizationServerSettings() {
        return ProviderSettings.builder()
                               .issuer(applicationProperties.getIssuerUrl())
                               .build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(final JdbcTemplate jdbcTemplate,
                                                           final RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, repository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(final JdbcTemplate jdbcTemplate,
                                                                         final RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, repository);
    }

    /**
     * Required for OIDC client registration endpoint
     */
    @Bean
    public JwtDecoder jwtDecoder(final JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthenticationManager authenticationManager(final AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}