package com.example.WebAuthn_Demo_App_2.model;

import com.webauthn4j.data.client.challenge.Challenge;

public record WebAuthnChallenge(
        String username,
        ChallengeType type,
        Challenge challenge,
        long createdAt
) {
}
