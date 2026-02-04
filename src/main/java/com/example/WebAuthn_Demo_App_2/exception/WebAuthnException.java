package com.example.WebAuthn_Demo_App_2.exception;

public class WebAuthnException extends RuntimeException {
    public WebAuthnException(String message, Throwable cause) {
        super(message, cause);
    }

    public WebAuthnException(String message) {
        super(message);
    }
}
