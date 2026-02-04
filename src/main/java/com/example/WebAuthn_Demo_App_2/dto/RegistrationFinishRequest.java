package com.example.WebAuthn_Demo_App_2.dto;

import java.util.Map;

public record RegistrationFinishRequest(String username, Map<String, Object> credential) {
}
