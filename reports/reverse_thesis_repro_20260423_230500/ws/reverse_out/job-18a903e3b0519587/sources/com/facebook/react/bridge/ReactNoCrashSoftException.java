package com.facebook.react.bridge;

/* JADX INFO: loaded from: classes.dex */
public class ReactNoCrashSoftException extends RuntimeException {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashSoftException(String str) {
        super(str);
        t2.j.f(str, "m");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashSoftException(Throwable th) {
        super(th);
        t2.j.f(th, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactNoCrashSoftException(String str, Throwable th) {
        super(str, th);
        t2.j.f(str, "m");
    }
}
