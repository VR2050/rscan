package com.facebook.react.bridge;

/* JADX INFO: loaded from: classes.dex */
public class JSApplicationCausedNativeException extends RuntimeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JSApplicationCausedNativeException(String str) {
        super(str);
        t2.j.f(str, "detailMessage");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JSApplicationCausedNativeException(String str, Throwable th) {
        super(str, th);
        t2.j.f(str, "detailMessage");
    }
}
