package com.stripe.android.exception;

/* JADX INFO: loaded from: classes3.dex */
public class PermissionException extends AuthenticationException {
    public PermissionException(String message, String requestId, Integer statusCode) {
        super(message, requestId, statusCode);
    }
}
