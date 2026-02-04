package com.example.WebAuthn_Demo_App_2.store;

import com.example.WebAuthn_Demo_App_2.model.ChallengeType;
import com.example.WebAuthn_Demo_App_2.model.WebAuthnChallenge;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ChallengeStore {

    private final Map<String, WebAuthnChallenge> challengeEntriesMap = new ConcurrentHashMap<>();

    public Challenge createAndStoreChallenge(String username, ChallengeType type) {
        Challenge challenge = new DefaultChallenge();
        WebAuthnChallenge entry = new WebAuthnChallenge(
                username,
                type, // registration or authentication
                challenge, // actual challenge
                System.currentTimeMillis() // timestamp
        );
        // Storing the challenge entry in a map
        challengeEntriesMap.put(challengeMapKey(username, type), entry);
        return challenge;
    }

    // Clears the challenge but also tries to match the challenge received with the stored challenge in existing map
    public WebAuthnChallenge getChallengeEntry(String username, ChallengeType type, Challenge clientChallenge) {
        // Clearing the challenge entry from the map if it exists
        WebAuthnChallenge entry = challengeEntriesMap.remove(challengeMapKey(username, type));
        if (entry == null) {
            throw new IllegalArgumentException("Missing challenge for user: " + username);
        }
        // If the actual challenge value is not the same, we do not move forward and throw an error
        if (!Arrays.equals(entry.challenge().getValue(), clientChallenge.getValue())) {
            throw new IllegalArgumentException("Challenge mismatch for user: " + username);
        }
        return entry;
    }


    // Register and authenticate will have different challenge entries, however the value will be the same
    private String challengeMapKey(String username, ChallengeType type) {
        return username + "|" + type;
    }
}
