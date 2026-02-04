package com.example.WebAuthn_Demo_App_2.service;

import com.example.WebAuthn_Demo_App_2.config.WebAuthnProperties;
import com.example.WebAuthn_Demo_App_2.dto.AuthenticationFinishRequest;
import com.example.WebAuthn_Demo_App_2.dto.AuthenticationFinishResponse;
import com.example.WebAuthn_Demo_App_2.dto.AuthenticationStartRequest;
import com.example.WebAuthn_Demo_App_2.dto.RegistrationFinishRequest;
import com.example.WebAuthn_Demo_App_2.dto.RegistrationFinishResponse;
import com.example.WebAuthn_Demo_App_2.dto.RegistrationStartRequest;
import com.example.WebAuthn_Demo_App_2.exception.WebAuthnException;
import com.example.WebAuthn_Demo_App_2.model.ChallengeType;
import com.example.WebAuthn_Demo_App_2.model.User;
import com.example.WebAuthn_Demo_App_2.model.WebAuthnChallenge;
import com.example.WebAuthn_Demo_App_2.store.ChallengeStore;
import com.example.WebAuthn_Demo_App_2.store.UserStore;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;

import java.util.ArrayList;
import java.util.List;

@Service
public class WebAuthnService {

    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    private final WebAuthnProperties properties;
    private final UserStore userStore;
    private final ChallengeStore challengeStore;

    public WebAuthnService(WebAuthnManager webAuthnManager,
                           ObjectConverter objectConverter,
                           WebAuthnProperties properties,
                           UserStore userStore,
                           ChallengeStore challengeStore) {
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = objectConverter;
        this.properties = properties;
        this.userStore = userStore;
        this.challengeStore = challengeStore;
    }

    public PublicKeyCredentialCreationOptions startRegistration(RegistrationStartRequest request) {

        // Find existing user details from the store or create new if user not found
        User user = userStore.getOrCreate(request.username(), resolveDisplayName(request));

        // Creating a default challenge and storing it into a map
        Challenge challenge = challengeStore.createAndStoreChallenge(
                user.getUsername(),
                ChallengeType.REGISTRATION
        );

        PublicKeyCredentialRpEntity rpEntity =
                new PublicKeyCredentialRpEntity(properties.getRpId(), properties.getRpName());
        PublicKeyCredentialUserEntity userEntity =
                new PublicKeyCredentialUserEntity(user.getUserId(), user.getUsername(), user.getDisplayName());

        List<PublicKeyCredentialParameters> pubKeyCredParams = getPublicKeyCredentialParams(); // type of key and algorithm identifier

        AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(
                null,
                ResidentKeyRequirement.PREFERRED,
                UserVerificationRequirement.PREFERRED
        );

        return new PublicKeyCredentialCreationOptions(
                rpEntity,
                userEntity,
                challenge,
                pubKeyCredParams,
                properties.getTimeoutMs(),
                userStore.getCredentialDescriptors(user.getUsername()), // credentials to be excluded
                authenticatorSelection,
                List.of(),
                AttestationConveyancePreference.NONE,
                null
        );
    }

    public RegistrationFinishResponse finishRegistration(RegistrationFinishRequest request) {

        // We convert credential data from request into the right format for webAuthnManager
        RegistrationData registrationData = parseRegistrationData(request);
        WebAuthnChallenge expectedChallengeEntry = getChallengeEntry(
                request.username(),
                ChallengeType.REGISTRATION,
                registrationData
        );
        ServerProperty serverProperty = serverProperty(expectedChallengeEntry.challenge());

        RegistrationParameters parameters = new RegistrationParameters(
                serverProperty,
                getPublicKeyCredentialParams(),
                false,
                true
        );

        try {
            // Verifying the credential and the challenge using webAuthnManager
            webAuthnManager.verify(registrationData, parameters);
        } catch (VerificationException e) {
            throw new WebAuthnException("Registration verification failed", e);
        }

        // Registration is successful at this point.

        CredentialRecord credentialRecord = new CredentialRecordImpl(
                registrationData.getAttestationObject(),
                registrationData.getCollectedClientData(),
                registrationData.getClientExtensions(),
                registrationData.getTransports()
        );

        // Adding the credential record to the usersMap
        userStore.addCredential(request.username(), credentialRecord);

        return new RegistrationFinishResponse(
                request.username(),
                Base64UrlUtil.encodeToString(credentialRecord.getAttestedCredentialData().getCredentialId()),
                credentialRecord.getCounter()
        );
    }

    public PublicKeyCredentialRequestOptions startAuthentication(AuthenticationStartRequest request) {
        User user = userStore.getRequired(request.username());
        Challenge challenge = challengeStore.createAndStoreChallenge(
                user.getUsername(),
                ChallengeType.AUTHENTICATION
        );

        List<PublicKeyCredentialDescriptor> allowCredentials = userStore.getCredentialDescriptors(user.getUsername());
        if (allowCredentials.isEmpty()) {
            throw new WebAuthnException("No credentials registered for user: " + user.getUsername());
        }

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                challenge,
                properties.getTimeoutMs(),
                properties.getRpId(),
                allowCredentials,
                UserVerificationRequirement.PREFERRED,
                null
        );

        return options;
    }

    public AuthenticationFinishResponse finishAuthentication(AuthenticationFinishRequest request) {
        AuthenticationData authenticationData = parseAuthenticationData(request);
        WebAuthnChallenge expectedChallenge = consumeChallenge(
                request.username(),
                ChallengeType.AUTHENTICATION,
                authenticationData
        );

        CredentialRecord credentialRecord =
                userStore.getCredential(request.username(), authenticationData.getCredentialId());

        List<byte[]> allowCredentialIds = new ArrayList<>();
        for (CredentialRecord record : userStore.getCredentials(request.username())) {
            allowCredentialIds.add(record.getAttestedCredentialData().getCredentialId());
        }

        AuthenticationParameters parameters = new AuthenticationParameters(
                serverProperty(expectedChallenge.challenge()),
                credentialRecord,
                allowCredentialIds,
                false,
                true
        );

        try {
            webAuthnManager.verify(authenticationData, parameters);
        } catch (VerificationException e) {
            throw new WebAuthnException("Authentication verification failed", e);
        }

        if (authenticationData.getAuthenticatorData() != null) {
            credentialRecord.setCounter(authenticationData.getAuthenticatorData().getSignCount());
        }

        return new AuthenticationFinishResponse(
                request.username(),
                Base64UrlUtil.encodeToString(credentialRecord.getAttestedCredentialData().getCredentialId()),
                credentialRecord.getCounter()
        );
    }

    private RegistrationData parseRegistrationData(RegistrationFinishRequest request) {
        if (request.credential() == null) {
            throw new WebAuthnException("Missing registration credential payload");
        }
        try {
            String credentialJsonString = objectConverter.getJsonMapper().writeValueAsString(request.credential());
            return webAuthnManager.parseRegistrationResponseJSON(credentialJsonString);
        } catch (JacksonException | DataConversionException e) {
            throw new WebAuthnException("Invalid registration credential payload", e);
        }
    }

    private AuthenticationData parseAuthenticationData(AuthenticationFinishRequest request) {
        if (request.credential() == null) {
            throw new WebAuthnException("Missing authentication credential payload");
        }
        try {
            String json = objectConverter.getJsonMapper().writeValueAsString(request.credential());
            return webAuthnManager.parseAuthenticationResponseJSON(json);
        } catch (JacksonException | DataConversionException e) {
            throw new WebAuthnException("Invalid authentication credential payload", e);
        }
    }

    private ServerProperty serverProperty(Challenge challenge) {
        return ServerProperty.builder()
                .origin(new Origin(properties.getOrigin()))
                .rpId(properties.getRpId())
                .challenge(challenge)
                .build();
    }

    private WebAuthnChallenge getChallengeEntry(String username,
                                       ChallengeType type,
                                       RegistrationData registrationData) {
        if (registrationData.getCollectedClientData() == null) {
            throw new WebAuthnException("Missing client data in registration response");
        }
        return challengeStore.getChallengeEntry(
                username,
                type,
                registrationData.getCollectedClientData().getChallenge()
        );
    }

    private WebAuthnChallenge consumeChallenge(String username,
                                       ChallengeType type,
                                       AuthenticationData authenticationData) {
        if (authenticationData.getCollectedClientData() == null) {
            throw new WebAuthnException("Missing client data in authentication response");
        }
        return challengeStore.getChallengeEntry(
                username,
                type,
                authenticationData.getCollectedClientData().getChallenge()
        );
    }

    private String resolveDisplayName(RegistrationStartRequest request) {
        if (request.displayName() != null && !request.displayName().isBlank()) {
            return request.displayName().trim();
        }
        return request.username();
    }

    private List<PublicKeyCredentialParameters> getPublicKeyCredentialParams() {
        return List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );
    }

}
