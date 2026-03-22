package com.alipay.android.phone.mrpc.core;

/* renamed from: com.alipay.android.phone.mrpc.core.p */
/* loaded from: classes.dex */
public final class C3156p extends C3161u {

    /* renamed from: c */
    private int f8573c;

    /* renamed from: d */
    private String f8574d;

    /* renamed from: e */
    private long f8575e;

    /* renamed from: f */
    private long f8576f;

    /* renamed from: g */
    private String f8577g;

    /* renamed from: h */
    private HttpUrlHeader f8578h;

    public C3156p(HttpUrlHeader httpUrlHeader, int i2, String str, byte[] bArr) {
        this.f8578h = httpUrlHeader;
        this.f8573c = i2;
        this.f8574d = str;
        this.f8599a = bArr;
    }

    /* renamed from: a */
    public final HttpUrlHeader m3698a() {
        return this.f8578h;
    }

    /* renamed from: a */
    public final void m3699a(long j2) {
        this.f8575e = j2;
    }

    /* renamed from: a */
    public final void m3700a(String str) {
        this.f8577g = str;
    }

    /* renamed from: b */
    public final void m3701b(long j2) {
        this.f8576f = j2;
    }
}
