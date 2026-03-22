package com.alipay.apmobilesecuritysdk.p389b;

import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.b.a */
/* loaded from: classes.dex */
public final class C3168a {

    /* renamed from: b */
    private static C3168a f8614b = new C3168a();

    /* renamed from: a */
    private int f8615a = 0;

    /* renamed from: a */
    public static C3168a m3734a() {
        return f8614b;
    }

    /* renamed from: a */
    public final void m3735a(int i2) {
        this.f8615a = i2;
    }

    /* renamed from: b */
    public final int m3736b() {
        return this.f8615a;
    }

    /* renamed from: c */
    public final String m3737c() {
        if (C4195m.m4840x(null)) {
            return null;
        }
        int i2 = this.f8615a;
        return i2 != 1 ? i2 != 3 ? i2 != 4 ? "https://mobilegw.alipay.com/mgw.htm" : "http://mobilegw.aaa.alipay.net/mgw.htm" : "http://mobilegw-1-64.test.alipay.net/mgw.htm" : "http://mobilegw.stable.alipay.net/mgw.htm";
    }
}
