package p005b.p085c.p086a.p087a;

import java.lang.reflect.Type;
import java.util.Date;

/* renamed from: b.c.a.a.c */
/* loaded from: classes.dex */
public final class C1334c implements InterfaceC1340i, InterfaceC1341j {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final Object mo340a(Object obj) {
        return Long.valueOf(((Date) obj).getTime());
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return Date.class.isAssignableFrom(cls);
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    public final Object mo342b(Object obj, Type type) {
        return new Date(((Long) obj).longValue());
    }
}
