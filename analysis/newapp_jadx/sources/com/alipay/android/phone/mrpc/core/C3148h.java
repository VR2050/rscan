package com.alipay.android.phone.mrpc.core;

import android.content.Context;

/* renamed from: com.alipay.android.phone.mrpc.core.h */
/* loaded from: classes.dex */
public final class C3148h extends AbstractC3163w {

    /* renamed from: a */
    private Context f8546a;

    public C3148h(Context context) {
        this.f8546a = context;
    }

    @Override // com.alipay.android.phone.mrpc.core.AbstractC3163w
    /* renamed from: a */
    public final <T> T mo3674a(Class<T> cls, C3138aa c3138aa) {
        return (T) new C3164x(new C3149i(this, c3138aa)).m3725a(cls);
    }
}
