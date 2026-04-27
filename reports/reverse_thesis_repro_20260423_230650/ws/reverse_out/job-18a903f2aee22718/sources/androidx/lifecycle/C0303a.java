package androidx.lifecycle;

import androidx.lifecycle.f;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: renamed from: androidx.lifecycle.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
final class C0303a {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    static C0303a f5125c = new C0303a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f5126a = new HashMap();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Map f5127b = new HashMap();

    /* JADX INFO: renamed from: androidx.lifecycle.a$a, reason: collision with other inner class name */
    static class C0073a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final Map f5128a = new HashMap();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final Map f5129b;

        C0073a(Map map) {
            this.f5129b = map;
            for (Map.Entry entry : map.entrySet()) {
                f.a aVar = (f.a) entry.getValue();
                List arrayList = (List) this.f5128a.get(aVar);
                if (arrayList == null) {
                    arrayList = new ArrayList();
                    this.f5128a.put(aVar, arrayList);
                }
                arrayList.add((b) entry.getKey());
            }
        }

        private static void b(List list, k kVar, f.a aVar, Object obj) {
            if (list != null) {
                for (int size = list.size() - 1; size >= 0; size--) {
                    ((b) list.get(size)).a(kVar, aVar, obj);
                }
            }
        }

        void a(k kVar, f.a aVar, Object obj) {
            b((List) this.f5128a.get(aVar), kVar, aVar, obj);
            b((List) this.f5128a.get(f.a.ON_ANY), kVar, aVar, obj);
        }
    }

    /* JADX INFO: renamed from: androidx.lifecycle.a$b */
    static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final int f5130a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final Method f5131b;

        b(int i3, Method method) {
            this.f5130a = i3;
            this.f5131b = method;
            method.setAccessible(true);
        }

        void a(k kVar, f.a aVar, Object obj) {
            try {
                int i3 = this.f5130a;
                if (i3 == 0) {
                    this.f5131b.invoke(obj, new Object[0]);
                } else if (i3 == 1) {
                    this.f5131b.invoke(obj, kVar);
                } else {
                    if (i3 != 2) {
                        return;
                    }
                    this.f5131b.invoke(obj, kVar, aVar);
                }
            } catch (IllegalAccessException e3) {
                throw new RuntimeException(e3);
            } catch (InvocationTargetException e4) {
                throw new RuntimeException("Failed to call observer method", e4.getCause());
            }
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return this.f5130a == bVar.f5130a && this.f5131b.getName().equals(bVar.f5131b.getName());
        }

        public int hashCode() {
            return (this.f5130a * 31) + this.f5131b.getName().hashCode();
        }
    }

    C0303a() {
    }

    private C0073a a(Class cls, Method[] methodArr) {
        int i3;
        C0073a c0073aC;
        Class superclass = cls.getSuperclass();
        HashMap map = new HashMap();
        if (superclass != null && (c0073aC = c(superclass)) != null) {
            map.putAll(c0073aC.f5129b);
        }
        for (Class<?> cls2 : cls.getInterfaces()) {
            for (Map.Entry entry : c(cls2).f5129b.entrySet()) {
                e(map, (b) entry.getKey(), (f.a) entry.getValue(), cls);
            }
        }
        if (methodArr == null) {
            methodArr = b(cls);
        }
        boolean z3 = false;
        for (Method method : methodArr) {
            q qVar = (q) method.getAnnotation(q.class);
            if (qVar != null) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length <= 0) {
                    i3 = 0;
                } else {
                    if (!k.class.isAssignableFrom(parameterTypes[0])) {
                        throw new IllegalArgumentException("invalid parameter type. Must be one and instanceof LifecycleOwner");
                    }
                    i3 = 1;
                }
                f.a aVarValue = qVar.value();
                if (parameterTypes.length > 1) {
                    if (!f.a.class.isAssignableFrom(parameterTypes[1])) {
                        throw new IllegalArgumentException("invalid parameter type. second arg must be an event");
                    }
                    if (aVarValue != f.a.ON_ANY) {
                        throw new IllegalArgumentException("Second arg is supported only for ON_ANY value");
                    }
                    i3 = 2;
                }
                if (parameterTypes.length > 2) {
                    throw new IllegalArgumentException("cannot have more than 2 params");
                }
                e(map, new b(i3, method), aVarValue, cls);
                z3 = true;
            }
        }
        C0073a c0073a = new C0073a(map);
        this.f5126a.put(cls, c0073a);
        this.f5127b.put(cls, Boolean.valueOf(z3));
        return c0073a;
    }

    private Method[] b(Class cls) {
        try {
            return cls.getDeclaredMethods();
        } catch (NoClassDefFoundError e3) {
            throw new IllegalArgumentException("The observer class has some methods that use newer APIs which are not available in the current OS version. Lifecycles cannot access even other methods so you should make sure that your observer classes only access framework classes that are available in your min API level OR use lifecycle:compiler annotation processor.", e3);
        }
    }

    private void e(Map map, b bVar, f.a aVar, Class cls) {
        f.a aVar2 = (f.a) map.get(bVar);
        if (aVar2 == null || aVar == aVar2) {
            if (aVar2 == null) {
                map.put(bVar, aVar);
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Method " + bVar.f5131b.getName() + " in " + cls.getName() + " already declared with different @OnLifecycleEvent value: previous value " + aVar2 + ", new value " + aVar);
    }

    C0073a c(Class cls) {
        C0073a c0073a = (C0073a) this.f5126a.get(cls);
        return c0073a != null ? c0073a : a(cls, null);
    }

    boolean d(Class cls) {
        Boolean bool = (Boolean) this.f5127b.get(cls);
        if (bool != null) {
            return bool.booleanValue();
        }
        Method[] methodArrB = b(cls);
        for (Method method : methodArrB) {
            if (((q) method.getAnnotation(q.class)) != null) {
                a(cls, methodArrB);
                return true;
            }
        }
        this.f5127b.put(cls, Boolean.FALSE);
        return false;
    }
}
