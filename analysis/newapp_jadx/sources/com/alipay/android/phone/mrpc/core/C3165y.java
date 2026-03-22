package com.alipay.android.phone.mrpc.core;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/* renamed from: com.alipay.android.phone.mrpc.core.y */
/* loaded from: classes.dex */
public final class C3165y implements InvocationHandler {

    /* renamed from: a */
    public InterfaceC3147g f8603a;

    /* renamed from: b */
    public Class<?> f8604b;

    /* renamed from: c */
    public C3166z f8605c;

    public C3165y(InterfaceC3147g interfaceC3147g, Class<?> cls, C3166z c3166z) {
        this.f8603a = interfaceC3147g;
        this.f8604b = cls;
        this.f8605c = c3166z;
    }

    @Override // java.lang.reflect.InvocationHandler
    public final Object invoke(Object obj, Method method, Object[] objArr) {
        return this.f8605c.m3726a(method, objArr);
    }
}
