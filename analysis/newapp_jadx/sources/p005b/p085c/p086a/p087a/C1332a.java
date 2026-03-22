package p005b.p085c.p086a.p087a;

import java.lang.reflect.Array;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import org.json.alipay.C5071a;

/* renamed from: b.c.a.a.a */
/* loaded from: classes.dex */
public final class C1332a implements InterfaceC1340i, InterfaceC1341j {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final Object mo340a(Object obj) {
        ArrayList arrayList = new ArrayList();
        for (Object obj2 : (Object[]) obj) {
            arrayList.add(C1337f.m346b(obj2));
        }
        return arrayList;
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return cls.isArray();
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    public final Object mo342b(Object obj, Type type) {
        if (!obj.getClass().equals(C5071a.class)) {
            return null;
        }
        C5071a c5071a = (C5071a) obj;
        if (type instanceof GenericArrayType) {
            throw new IllegalArgumentException("Does not support generic array!");
        }
        Class<?> componentType = ((Class) type).getComponentType();
        int m5700a = c5071a.m5700a();
        Object newInstance = Array.newInstance(componentType, m5700a);
        for (int i2 = 0; i2 < m5700a; i2++) {
            Array.set(newInstance, i2, C1336e.m343a(c5071a.m5701a(i2), componentType));
        }
        return newInstance;
    }
}
