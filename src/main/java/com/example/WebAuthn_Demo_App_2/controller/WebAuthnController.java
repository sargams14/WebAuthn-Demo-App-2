package com.example.WebAuthn_Demo_App_2.controller;

import com.example.WebAuthn_Demo_App_2.dto.AuthenticationFinishRequest;
import com.example.WebAuthn_Demo_App_2.dto.AuthenticationFinishResponse;
import com.example.WebAuthn_Demo_App_2.dto.AuthenticationStartRequest;
import com.example.WebAuthn_Demo_App_2.dto.RegistrationFinishRequest;
import com.example.WebAuthn_Demo_App_2.dto.RegistrationFinishResponse;
import com.example.WebAuthn_Demo_App_2.dto.RegistrationStartRequest;
import com.example.WebAuthn_Demo_App_2.service.WebAuthnService;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/webauthn")
public class WebAuthnController {

    private final WebAuthnService webAuthnService;

    public WebAuthnController(WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    // Starting registration, sending public key cred creation options to the client
    @PostMapping("/register/options")
    public ResponseEntity<PublicKeyCredentialCreationOptions> registrationOptions(
            @RequestBody RegistrationStartRequest request) {
        PublicKeyCredentialCreationOptions options = webAuthnService.startRegistration(request);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(options);
    }

    // Completing user registration
    @PostMapping("/register/finish")
    public ResponseEntity<RegistrationFinishResponse> register(@RequestBody RegistrationFinishRequest request) {
        RegistrationFinishResponse response = webAuthnService.finishRegistration(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // Starting user authentication, sending public key cred request options to the client
    @PostMapping("/authenticate/options")
    public ResponseEntity<PublicKeyCredentialRequestOptions> authenticationOptions(
            @RequestBody AuthenticationStartRequest request) {
        PublicKeyCredentialRequestOptions options = webAuthnService.startAuthentication(request);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(options);
    }

    // Completing user authentication using passkey
    @PostMapping("/authenticate/finish")
    public ResponseEntity<AuthenticationFinishResponse> authenticate(@RequestBody AuthenticationFinishRequest request) {
        AuthenticationFinishResponse response = webAuthnService.finishAuthentication(request);
        return ResponseEntity.ok(response);
    }
}
