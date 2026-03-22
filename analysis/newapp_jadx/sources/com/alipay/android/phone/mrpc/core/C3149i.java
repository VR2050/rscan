package com.alipay.android.phone.mrpc.core;

import android.content.Context;

/* renamed from: com.alipay.android.phone.mrpc.core.i */
/* loaded from: classes.dex */
public final class C3149i implements InterfaceC3147g {

    /* renamed from: a */
    public final /* synthetic */ C3138aa f8547a;

    /* renamed from: b */
    public final /* synthetic */ C3148h f8548b;

    public C3149i(C3148h c3148h, C3138aa c3138aa) {
        this.f8548b = c3148h;
        this.f8547a = c3138aa;
    }

    @Override // com.alipay.android.phone.mrpc.core.InterfaceC3147g
    /* renamed from: a */
    public final String mo3669a() {
        return this.f8547a.m3651a();
    }

    @Override // com.alipay.android.phone.mrpc.core.InterfaceC3147g
    /* renamed from: b */
    public final InterfaceC3139ab mo3670b() {
        Context context;
        context = this.f8548b.f8546a;
        return C3152l.m3681a(context.getApplicationContext());
    }

    @Override // com.alipay.android.phone.mrpc.core.InterfaceC3147g
    /* renamed from: c */
    public final C3138aa mo3671c() {
        return this.f8547a;
    }

    @Override // com.alipay.android.phone.mrpc.core.InterfaceC3147g
    /* renamed from: d */
    public final boolean mo3672d() {
        return this.f8547a.m3654c();
    }
}
