package p005b.p085c.p086a.p087a;

import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.TreeMap;
import org.json.alipay.C5072b;

/* renamed from: b.c.a.a.g */
/* loaded from: classes.dex */
public final class C1338g implements InterfaceC1340i, InterfaceC1341j {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final Object mo340a(Object obj) {
        TreeMap treeMap = new TreeMap();
        Class<?> cls = obj.getClass();
        while (true) {
            Field[] declaredFields = cls.getDeclaredFields();
            if (cls.equals(Object.class)) {
                return treeMap;
            }
            if (declaredFields != null && declaredFields.length > 0) {
                for (Field field : declaredFields) {
                    Object obj2 = null;
                    if (field != null && !"this$0".equals(field.getName())) {
                        boolean isAccessible = field.isAccessible();
                        field.setAccessible(true);
                        Object obj3 = field.get(obj);
                        if (obj3 != null) {
                            field.setAccessible(isAccessible);
                            obj2 = C1337f.m346b(obj3);
                        }
                    }
                    if (obj2 != null) {
                        treeMap.put(field.getName(), obj2);
                    }
                }
            }
            cls = cls.getSuperclass();
        }
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return true;
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    public final Object mo342b(Object obj, Type type) {
        if (!obj.getClass().equals(C5072b.class)) {
            return null;
        }
        C5072b c5072b = (C5072b) obj;
        Class cls = (Class) type;
        Object newInstance = cls.newInstance();
        while (!cls.equals(Object.class)) {
            Field[] declaredFields = cls.getDeclaredFields();
            if (declaredFields != null && declaredFields.length > 0) {
                for (Field field : declaredFields) {
                    String name = field.getName();
                    Type genericType = field.getGenericType();
                    if (c5072b.m5707b(name)) {
                        field.setAccessible(true);
                        field.set(newInstance, C1336e.m343a(c5072b.m5705a(name), genericType));
                    }
                }
            }
            cls = cls.getSuperclass();
        }
        return newInstance;
    }
}
