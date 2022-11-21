package org.kg.authserver.config;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Setter
@Getter
@Component
@ConfigurationProperties(prefix = "authorization-server.config", ignoreUnknownFields = false)
@ConfigurationPropertiesScan
@NoArgsConstructor(access = AccessLevel.PRIVATE)
class ApplicationProperties {

    private String issuerUrl;
    private List<Client> clients;
    private KeyStoreProperties keyStoreProperties;

    @Getter
    @Setter
    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    static final class KeyStoreProperties {
        private String location;
        private String password;
        private String alias;
    }

    @Getter
    @Setter
    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    static final class Client {
        private static final Map<String, ClientAuthenticationMethod> DEFAULT_CLIENT_AUTHENTICATION_METHODS
                = Map.ofEntries(Map.entry(ClientAuthenticationMethod.NONE.getValue(), ClientAuthenticationMethod.NONE),
                                Map.entry(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                                          ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                                Map.entry(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue(),
                                          ClientAuthenticationMethod.CLIENT_SECRET_JWT),
                                Map.entry(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(),
                                          ClientAuthenticationMethod.CLIENT_SECRET_POST),
                                Map.entry(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                                          ClientAuthenticationMethod.PRIVATE_KEY_JWT));
        private static final Map<String, AuthorizationGrantType> DEFAULT_CLIENT_AUTHORIZATION_GRANT_TYPES
                = Map.ofEntries(Map.entry(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                                          AuthorizationGrantType.AUTHORIZATION_CODE),
                                Map.entry(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
                                          AuthorizationGrantType.CLIENT_CREDENTIALS),
                                Map.entry(AuthorizationGrantType.PASSWORD.getValue(), AuthorizationGrantType.PASSWORD),
                                Map.entry(AuthorizationGrantType.JWT_BEARER.getValue(),
                                          AuthorizationGrantType.JWT_BEARER),
                                Map.entry(AuthorizationGrantType.REFRESH_TOKEN.getValue(),
                                          AuthorizationGrantType.REFRESH_TOKEN));

        private String clientId;
        private String clientSecret;
        private Set<String> redirectUris;
        private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
        private Set<AuthorizationGrantType> authorizationGrantTypes;
        private Set<String> scopes;

        public Consumer<Set<ClientAuthenticationMethod>> getClientAuthenticationMethods() {
            return consumer -> consumer.addAll(this.clientAuthenticationMethods);
        }

        public void setClientAuthenticationMethods(final Set<String> clientAuthenticationMethods) {
            this.clientAuthenticationMethods = clientAuthenticationMethods.stream()
                                                                          .map(method -> DEFAULT_CLIENT_AUTHENTICATION_METHODS.getOrDefault(
                                                                                  method,
                                                                                  new ClientAuthenticationMethod(
                                                                                          method)))
                                                                          .collect(Collectors.toSet());
        }

        public Consumer<Set<AuthorizationGrantType>> getAuthorizationGrantTypes() {
            return consumer -> consumer.addAll(this.authorizationGrantTypes);
        }

        public void setAuthorizationGrantTypes(final Set<String> authorizationGrantTypes) {
            this.authorizationGrantTypes = authorizationGrantTypes.stream()
                                                                  .map(method -> DEFAULT_CLIENT_AUTHORIZATION_GRANT_TYPES.getOrDefault(
                                                                          method, new AuthorizationGrantType(method)))
                                                                  .collect(Collectors.toSet());
        }

        public Consumer<Set<String>> getRedirectUris() {
            return consumer -> consumer.addAll(this.redirectUris);
        }

        public Consumer<Set<String>> getScopes() {
            return consumer -> consumer.addAll(this.scopes);
        }

        RegisteredClient asRegisteredClient(final PasswordEncoder encoder) {
            return RegisteredClient.withId(UUID.randomUUID()
                                               .toString())
                                   .clientId(getClientId())
                                   .clientSecret(encoder.encode(getClientSecret()))
                                   .clientAuthenticationMethods(getClientAuthenticationMethods())
                                   .authorizationGrantTypes(getAuthorizationGrantTypes())
                                   .redirectUris(getRedirectUris())
                                   .scopes(getScopes())
                                   .clientSettings(ClientSettings.builder()
                                                                 .requireAuthorizationConsent(true)
                                                                 .build())
                                   .build();
        }
    }
}
