package com.example.WebAuthn_Demo_App_2.model;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.util.Base64UrlUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class User {
    private final String username;
    private final String displayName;
    private final byte[] userId;
    private final Map<String, CredentialRecord> credentialRecords = new ConcurrentHashMap<>();

    public User(String username, String displayName, byte[] userId) {
        this.username = username;
        this.displayName = displayName;
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public byte[] getUserId() {
        return userId;
    }

    public void addCredential(CredentialRecord credentialRecord) {
        String key = Base64UrlUtil.encodeToString(credentialRecord.getAttestedCredentialData().getCredentialId());
        credentialRecords.put(key, credentialRecord);
    }

    public CredentialRecord getCredentialById(byte[] credentialId) {
        String key = Base64UrlUtil.encodeToString(credentialId);
        return credentialRecords.get(key);
    }

    public List<CredentialRecord> getCredentials() {
        return new ArrayList<>(credentialRecords.values());
    }

    public List<PublicKeyCredentialDescriptor> getCredentialDescriptors() {
        List<PublicKeyCredentialDescriptor> descriptors = new ArrayList<>();
        for (CredentialRecord credentialRecord : credentialRecords.values()) {
            descriptors.add(new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    credentialRecord.getAttestedCredentialData().getCredentialId(),
                    null
            ));
        }
        return descriptors;
    }
}
