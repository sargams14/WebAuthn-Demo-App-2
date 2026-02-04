package com.example.WebAuthn_Demo_App_2.store;

import com.example.WebAuthn_Demo_App_2.model.User;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class UserStore {

    private final Map<String, User> usersMap = new ConcurrentHashMap<>();

    // For generating random numbers that are cryptographically strong
    private final SecureRandom secureRandom;

    public UserStore(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    public User getOrCreate(String username, String displayName) {
        // Finding by username, creates new user if not present, generates a userId in bytes
        return usersMap.computeIfAbsent(username, key -> new User(key, displayName, generateUserId()));
    }

    // Adding null check to all username conditions
    public User getRequired(String username) {
        User user = usersMap.get(username);
        if (user == null) {
            throw new IllegalArgumentException("User not found: " + username);
        }
        return user;
    }

    public void addCredential(String username, CredentialRecord credentialRecord) {
        getRequired(username).addCredential(credentialRecord);
    }

    public CredentialRecord getCredential(String username, byte[] credentialId) {
        CredentialRecord record = getRequired(username).getCredentialById(credentialId);
        if (record == null) {
            throw new IllegalArgumentException("Unknown credential for user: " + username);
        }
        return record;
    }

    public List<PublicKeyCredentialDescriptor> getCredentialDescriptors(String username) {
        return getRequired(username).getCredentialDescriptors();
    }

    public List<CredentialRecord> getCredentials(String username) {
        return getRequired(username).getCredentials();
    }

    private byte[] generateUserId() {
        byte[] userId = new byte[32];
        secureRandom.nextBytes(userId);
        return userId;
    }
}
