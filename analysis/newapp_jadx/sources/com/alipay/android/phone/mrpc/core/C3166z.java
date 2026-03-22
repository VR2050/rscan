package com.alipay.android.phone.mrpc.core;

import android.os.Looper;
import com.alipay.android.phone.mrpc.core.p387a.C3135d;
import com.alipay.android.phone.mrpc.core.p387a.C3136e;
import com.alipay.mobile.framework.service.annotation.OperationType;
import com.alipay.mobile.framework.service.annotation.ResetCookie;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.alipay.android.phone.mrpc.core.z */
/* loaded from: classes.dex */
public final class C3166z {

    /* renamed from: a */
    private static final ThreadLocal<Object> f8606a = new ThreadLocal<>();

    /* renamed from: b */
    private static final ThreadLocal<Map<String, Object>> f8607b = new ThreadLocal<>();

    /* renamed from: c */
    private byte f8608c = 0;

    /* renamed from: d */
    private AtomicInteger f8609d = new AtomicInteger();

    /* renamed from: e */
    private C3164x f8610e;

    public C3166z(C3164x c3164x) {
        this.f8610e = c3164x;
    }

    /* renamed from: a */
    public final Object m3726a(Method method, Object[] objArr) {
        if (Looper.myLooper() != null && Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalThreadStateException("can't in main thread call rpc .");
        }
        OperationType operationType = (OperationType) method.getAnnotation(OperationType.class);
        boolean z = method.getAnnotation(ResetCookie.class) != null;
        Type genericReturnType = method.getGenericReturnType();
        method.getAnnotations();
        ThreadLocal<Object> threadLocal = f8606a;
        threadLocal.set(null);
        ThreadLocal<Map<String, Object>> threadLocal2 = f8607b;
        threadLocal2.set(null);
        if (operationType == null) {
            throw new IllegalStateException("OperationType must be set.");
        }
        String value = operationType.value();
        int incrementAndGet = this.f8609d.incrementAndGet();
        try {
            if (this.f8608c == 0) {
                C3136e c3136e = new C3136e(incrementAndGet, value, objArr);
                if (threadLocal2.get() != null) {
                    c3136e.mo3649a(threadLocal2.get());
                }
                byte[] bArr = (byte[]) new C3150j(this.f8610e.m3724a(), method, incrementAndGet, value, c3136e.mo3650a(), z).mo3675a();
                threadLocal2.set(null);
                Object mo3648a = new C3135d(genericReturnType, bArr).mo3648a();
                if (genericReturnType != Void.TYPE) {
                    threadLocal.set(mo3648a);
                }
            }
            return threadLocal.get();
        } catch (RpcException e2) {
            e2.setOperationType(value);
            throw e2;
        }
    }
}
