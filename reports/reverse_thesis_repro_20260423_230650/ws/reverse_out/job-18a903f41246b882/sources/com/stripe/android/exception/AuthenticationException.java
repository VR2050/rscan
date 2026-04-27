package com.stripe.android.exception;

/* JADX INFO: loaded from: classes3.dex */
public class AuthenticationException extends StripeException {
    public AuthenticationException(String message, String requestId, Integer statusCode) {
        super(message, requestId, statusCode);
    }
}
