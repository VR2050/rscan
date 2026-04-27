package com.facebook.react.uimanager;

import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: renamed from: com.facebook.react.uimanager.s0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0469s0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final ReadableMap f7757a;

    public C0469s0(ReadableMap readableMap) {
        this.f7757a = readableMap;
    }

    public boolean a(String str, boolean z3) {
        return this.f7757a.isNull(str) ? z3 : this.f7757a.getBoolean(str);
    }

    public String b(String str) {
        return this.f7757a.getString(str);
    }

    public boolean c(String str) {
        return this.f7757a.hasKey(str);
    }

    public String toString() {
        return "{ " + getClass().getSimpleName() + ": " + this.f7757a.toString() + " }";
    }
}
