package com.facebook.react.bridge;

/* JADX INFO: loaded from: classes.dex */
public final class RetryableMountingLayerException extends RuntimeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RetryableMountingLayerException(String str) {
        super(str);
        t2.j.f(str, "msg");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RetryableMountingLayerException(Throwable th) {
        super(th);
        t2.j.f(th, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RetryableMountingLayerException(String str, Throwable th) {
        super(str, th);
        t2.j.f(str, "msg");
    }
}
