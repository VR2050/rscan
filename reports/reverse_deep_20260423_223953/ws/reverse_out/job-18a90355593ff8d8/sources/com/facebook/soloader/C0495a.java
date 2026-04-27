package com.facebook.soloader;

import android.content.Context;
import android.os.StrictMode;
import java.io.File;

/* JADX INFO: renamed from: com.facebook.soloader.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0495a extends E implements w {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f8342a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private C0500f f8343b;

    public C0495a(Context context, int i3) {
        this.f8342a = i3;
        this.f8343b = new C0500f(f(context), i3);
    }

    private static File f(Context context) {
        return new File(context.getApplicationInfo().nativeLibraryDir);
    }

    @Override // com.facebook.soloader.w
    public E a(Context context) {
        this.f8343b = new C0500f(f(context), this.f8342a | 1);
        return this;
    }

    @Override // com.facebook.soloader.E
    public String c() {
        return "ApplicationSoSource";
    }

    @Override // com.facebook.soloader.E
    public int d(String str, int i3, StrictMode.ThreadPolicy threadPolicy) {
        return this.f8343b.d(str, i3, threadPolicy);
    }

    @Override // com.facebook.soloader.E
    protected void e(int i3) {
        this.f8343b.e(i3);
    }

    @Override // com.facebook.soloader.E
    public String toString() {
        return c() + "[" + this.f8343b.toString() + "]";
    }
}
