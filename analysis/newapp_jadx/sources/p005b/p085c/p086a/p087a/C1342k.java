package p005b.p085c.p086a.p087a;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;
import org.json.alipay.C5071a;

/* renamed from: b.c.a.a.k */
/* loaded from: classes.dex */
public final class C1342k implements InterfaceC1340i {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return Set.class.isAssignableFrom(cls);
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    public final Object mo342b(Object obj, Type type) {
        if (!obj.getClass().equals(C5071a.class)) {
            return null;
        }
        C5071a c5071a = (C5071a) obj;
        HashSet hashSet = new HashSet();
        Class cls = type instanceof ParameterizedType ? ((ParameterizedType) type).getActualTypeArguments()[0] : Object.class;
        for (int i2 = 0; i2 < c5071a.m5700a(); i2++) {
            hashSet.add(C1336e.m343a(c5071a.m5701a(i2), cls));
        }
        return hashSet;
    }
}
