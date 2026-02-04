package com.example.WebAuthn_Demo_App_2.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.converter.util.ObjectConverter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.JacksonModule;

import java.security.SecureRandom;

@Configuration
@EnableConfigurationProperties(WebAuthnProperties.class)
public class WebAuthnConfig {

    @Bean
    public ObjectConverter objectConverter() {
        return new ObjectConverter();
    }

    @Bean
    public JacksonModule webAuthnJsonModule(ObjectConverter objectConverter) {
        return new WebAuthnJSONModule(objectConverter);
    }

    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    @Bean
    public SecureRandom secureRandom() {
        return new SecureRandom();
    }
}
