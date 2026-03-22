package p005b.p085c.p086a.p087a;

import java.lang.reflect.Type;

/* renamed from: b.c.a.a.d */
/* loaded from: classes.dex */
public final class C1335d implements InterfaceC1340i, InterfaceC1341j {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final Object mo340a(Object obj) {
        return ((Enum) obj).name();
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return Enum.class.isAssignableFrom(cls);
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    public final Object mo342b(Object obj, Type type) {
        return Enum.valueOf((Class) type, obj.toString());
    }
}
