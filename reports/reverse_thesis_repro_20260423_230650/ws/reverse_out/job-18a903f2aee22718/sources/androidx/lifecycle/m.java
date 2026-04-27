package androidx.lifecycle;

import i2.AbstractC0586n;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final m f5154a = new m();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Map f5155b = new HashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final Map f5156c = new HashMap();

    private m() {
    }

    private final InterfaceC0306d a(Constructor constructor, Object obj) {
        try {
            Object objNewInstance = constructor.newInstance(obj);
            t2.j.e(objNewInstance, "{\n            constructo…tance(`object`)\n        }");
            androidx.activity.result.d.a(objNewInstance);
            return null;
        } catch (IllegalAccessException e3) {
            throw new RuntimeException(e3);
        } catch (InstantiationException e4) {
            throw new RuntimeException(e4);
        } catch (InvocationTargetException e5) {
            throw new RuntimeException(e5);
        }
    }

    private final Constructor b(Class cls) {
        try {
            Package r02 = cls.getPackage();
            String canonicalName = cls.getCanonicalName();
            String name = r02 != null ? r02.getName() : "";
            t2.j.e(name, "fullPackage");
            if (name.length() != 0) {
                t2.j.e(canonicalName, "name");
                canonicalName = canonicalName.substring(name.length() + 1);
                t2.j.e(canonicalName, "this as java.lang.String).substring(startIndex)");
            }
            t2.j.e(canonicalName, "if (fullPackage.isEmpty(…g(fullPackage.length + 1)");
            String strC = c(canonicalName);
            if (name.length() != 0) {
                strC = name + '.' + strC;
            }
            Class<?> cls2 = Class.forName(strC);
            t2.j.d(cls2, "null cannot be cast to non-null type java.lang.Class<out androidx.lifecycle.GeneratedAdapter>");
            Constructor<?> declaredConstructor = cls2.getDeclaredConstructor(cls);
            if (declaredConstructor.isAccessible()) {
                return declaredConstructor;
            }
            declaredConstructor.setAccessible(true);
            return declaredConstructor;
        } catch (ClassNotFoundException unused) {
            return null;
        } catch (NoSuchMethodException e3) {
            throw new RuntimeException(e3);
        }
    }

    public static final String c(String str) {
        t2.j.f(str, "className");
        return z2.g.q(str, ".", "_", false, 4, null) + "_LifecycleAdapter";
    }

    private final int d(Class cls) {
        Map map = f5155b;
        Integer num = (Integer) map.get(cls);
        if (num != null) {
            return num.intValue();
        }
        int iG = g(cls);
        map.put(cls, Integer.valueOf(iG));
        return iG;
    }

    private final boolean e(Class cls) {
        return cls != null && j.class.isAssignableFrom(cls);
    }

    public static final i f(Object obj) {
        t2.j.f(obj, "object");
        boolean z3 = obj instanceof i;
        boolean z4 = obj instanceof InterfaceC0304b;
        if (z3 && z4) {
            return new DefaultLifecycleObserverAdapter((InterfaceC0304b) obj, (i) obj);
        }
        if (z4) {
            return new DefaultLifecycleObserverAdapter((InterfaceC0304b) obj, null);
        }
        if (z3) {
            return (i) obj;
        }
        Class<?> cls = obj.getClass();
        m mVar = f5154a;
        if (mVar.d(cls) != 2) {
            return new ReflectiveGenericLifecycleObserver(obj);
        }
        Object obj2 = f5156c.get(cls);
        t2.j.c(obj2);
        List list = (List) obj2;
        if (list.size() == 1) {
            mVar.a((Constructor) list.get(0), obj);
            return new SingleGeneratedAdapterObserver(null);
        }
        int size = list.size();
        InterfaceC0306d[] interfaceC0306dArr = new InterfaceC0306d[size];
        for (int i3 = 0; i3 < size; i3++) {
            f5154a.a((Constructor) list.get(i3), obj);
            interfaceC0306dArr[i3] = null;
        }
        return new CompositeGeneratedAdaptersObserver(interfaceC0306dArr);
    }

    private final int g(Class cls) {
        ArrayList arrayList;
        if (cls.getCanonicalName() == null) {
            return 1;
        }
        Constructor constructorB = b(cls);
        if (constructorB != null) {
            f5156c.put(cls, AbstractC0586n.b(constructorB));
            return 2;
        }
        if (C0303a.f5125c.d(cls)) {
            return 1;
        }
        Class superclass = cls.getSuperclass();
        if (e(superclass)) {
            t2.j.e(superclass, "superclass");
            if (d(superclass) == 1) {
                return 1;
            }
            Object obj = f5156c.get(superclass);
            t2.j.c(obj);
            arrayList = new ArrayList((Collection) obj);
        } else {
            arrayList = null;
        }
        Class<?>[] interfaces = cls.getInterfaces();
        t2.j.e(interfaces, "klass.interfaces");
        for (Class<?> cls2 : interfaces) {
            if (e(cls2)) {
                t2.j.e(cls2, "intrface");
                if (d(cls2) == 1) {
                    return 1;
                }
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                Object obj2 = f5156c.get(cls2);
                t2.j.c(obj2);
                arrayList.addAll((Collection) obj2);
            }
        }
        if (arrayList == null) {
            return 1;
        }
        f5156c.put(cls, arrayList);
        return 2;
    }
}
