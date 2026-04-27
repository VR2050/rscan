package com.facebook.react.common;

import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class JavascriptException extends RuntimeException {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private String f6641b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public JavascriptException(String str) {
        super(str);
        j.f(str, "jsStackTrace");
    }

    public final void a(String str) {
        this.f6641b = str;
    }
}
