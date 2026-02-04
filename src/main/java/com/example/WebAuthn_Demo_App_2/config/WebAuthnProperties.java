package com.example.WebAuthn_Demo_App_2.config;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "webauthn")
public class WebAuthnProperties {

    private String rpId;
    private String rpName;
    private String origin;
    private long timeoutMs;

    @PostConstruct
    public void validate() {
        if (isBlank(rpId)) {
            throw new IllegalStateException("webauthn.rp-id must be configured");
        }
        if (isBlank(rpName)) {
            throw new IllegalStateException("webauthn.rp-name must be configured");
        }
        if (isBlank(origin)) {
            throw new IllegalStateException("webauthn.origin must be configured");
        }
        if (timeoutMs <= 0) {
            throw new IllegalStateException("webauthn.timeout-ms must be greater than 0");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public void setRpName(String rpName) {
        this.rpName = rpName;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public long getTimeoutMs() {
        return timeoutMs;
    }

    public void setTimeoutMs(long timeoutMs) {
        this.timeoutMs = timeoutMs;
    }
}
