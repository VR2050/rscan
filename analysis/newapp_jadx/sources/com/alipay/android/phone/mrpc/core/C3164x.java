package com.alipay.android.phone.mrpc.core;

import java.lang.reflect.Proxy;

/* renamed from: com.alipay.android.phone.mrpc.core.x */
/* loaded from: classes.dex */
public final class C3164x {

    /* renamed from: a */
    private InterfaceC3147g f8601a;

    /* renamed from: b */
    private C3166z f8602b = new C3166z(this);

    public C3164x(InterfaceC3147g interfaceC3147g) {
        this.f8601a = interfaceC3147g;
    }

    /* renamed from: a */
    public final InterfaceC3147g m3724a() {
        return this.f8601a;
    }

    /* renamed from: a */
    public final <T> T m3725a(Class<T> cls) {
        return (T) Proxy.newProxyInstance(cls.getClassLoader(), new Class[]{cls}, new C3165y(this.f8601a, cls, this.f8602b));
    }
}
