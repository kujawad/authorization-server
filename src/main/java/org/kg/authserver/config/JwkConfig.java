package org.kg.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
@AllArgsConstructor
public class JwkConfig {

    private final ApplicationProperties properties;

    private KeyPair getKeyPair() {
        final ApplicationProperties.KeyStoreProperties keyStoreProperties = properties.getKeyStoreProperties();
        final ClassPathResource keystoreFile = new ClassPathResource(keyStoreProperties.getLocation());
        final char[] password = keyStoreProperties.getPassword()
                                                  .toCharArray();
        final String alias = keyStoreProperties.getAlias();

        final KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(keystoreFile.getFile(), password);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }

        final PrivateKey key;
        try {
            key = (PrivateKey) keystore.getKey(alias, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }

        final Certificate cert;
        try {
            cert = keystore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        return new KeyPair(cert.getPublicKey(), key);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        final KeyPair keyPair = getKeyPair();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        final RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
                                                           .keyID("authorization-server-key-kid")
                                                           .build();
        final JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
}
