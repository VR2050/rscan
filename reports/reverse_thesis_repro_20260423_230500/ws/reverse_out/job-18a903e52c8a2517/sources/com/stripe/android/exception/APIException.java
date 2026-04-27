package com.stripe.android.exception;

/* JADX INFO: loaded from: classes3.dex */
public class APIException extends StripeException {
    public APIException(String message, String requestId, Integer statusCode, Throwable e) {
        super(message, requestId, statusCode, e);
    }
}
