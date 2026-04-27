package com.stripe.android.exception;

/* JADX INFO: loaded from: classes3.dex */
public class RateLimitException extends InvalidRequestException {
    public RateLimitException(String message, String param, String requestId, Integer statusCode, Throwable e) {
        super(message, param, requestId, statusCode, e);
    }
}
