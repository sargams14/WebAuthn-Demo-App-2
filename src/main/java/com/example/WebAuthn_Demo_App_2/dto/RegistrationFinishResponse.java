package com.example.WebAuthn_Demo_App_2.dto;

public record RegistrationFinishResponse(
        String username,
        String credentialId,
        long signCount
) {
}
