package com.facebook.react.uimanager;

import android.content.Context;
import android.view.View;
import com.facebook.react.bridge.ColorPropConverter;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.DynamicFromObject;
import com.facebook.react.bridge.JSApplicationIllegalArgumentException;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
abstract class X0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final Map f7539a = new HashMap();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Map f7540b = new HashMap();

    class a extends ThreadLocal {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f7541a;

        a(int i3) {
            this.f7541a = i3;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // java.lang.ThreadLocal
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Object[] initialValue() {
            return new Object[this.f7541a];
        }
    }

    private static class b extends m {
        public b(K1.a aVar, Method method) {
            super(aVar, "Array", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return (ReadableArray) obj;
        }
    }

    private static class c extends m {

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final boolean f7542i;

        public c(K1.a aVar, Method method, boolean z3) {
            super(aVar, "boolean", method);
            this.f7542i = z3;
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return obj == null ? this.f7542i : ((Boolean) obj).booleanValue() ? Boolean.TRUE : Boolean.FALSE;
        }
    }

    private static class d extends m {
        public d(K1.a aVar, Method method) {
            super(aVar, "boolean", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            if (obj != null) {
                return ((Boolean) obj).booleanValue() ? Boolean.TRUE : Boolean.FALSE;
            }
            return null;
        }
    }

    private static class e extends m {
        public e(K1.a aVar, Method method) {
            super(aVar, "mixed", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            if (obj != null) {
                return ColorPropConverter.getColor(obj, context);
            }
            return null;
        }

        public e(K1.b bVar, Method method, int i3) {
            super(bVar, "mixed", method, i3);
        }
    }

    private static class f extends m {
        public f(K1.a aVar, Method method) {
            super(aVar, "number", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            if (obj != null) {
                return obj instanceof Double ? Integer.valueOf(((Double) obj).intValue()) : (Integer) obj;
            }
            return null;
        }

        public f(K1.b bVar, Method method, int i3) {
            super(bVar, "number", method, i3);
        }
    }

    private static class i extends m {
        public i(K1.a aVar, Method method) {
            super(aVar, "mixed", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return obj instanceof Dynamic ? obj : new DynamicFromObject(obj);
        }

        public i(K1.b bVar, Method method, int i3) {
            super(bVar, "mixed", method, i3);
        }
    }

    private static class l extends m {
        public l(K1.a aVar, Method method) {
            super(aVar, "Map", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return (ReadableMap) obj;
        }
    }

    private static class n extends m {
        public n(K1.a aVar, Method method) {
            super(aVar, "String", method);
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return (String) obj;
        }
    }

    public static void b() {
        f7539a.clear();
        f7540b.clear();
    }

    private static m c(K1.a aVar, Method method, Class cls) {
        if (cls == Dynamic.class) {
            return new i(aVar, method);
        }
        if (cls == Boolean.TYPE) {
            return new c(aVar, method, aVar.defaultBoolean());
        }
        if (cls == Integer.TYPE) {
            return "Color".equals(aVar.customType()) ? new g(aVar, method, aVar.defaultInt()) : new k(aVar, method, aVar.defaultInt());
        }
        if (cls == Float.TYPE) {
            return new j(aVar, method, aVar.defaultFloat());
        }
        if (cls == Double.TYPE) {
            return new h(aVar, method, aVar.defaultDouble());
        }
        if (cls == String.class) {
            return new n(aVar, method);
        }
        if (cls == Boolean.class) {
            return new d(aVar, method);
        }
        if (cls == Integer.class) {
            return "Color".equals(aVar.customType()) ? new e(aVar, method) : new f(aVar, method);
        }
        if (cls == ReadableArray.class) {
            return new b(aVar, method);
        }
        if (cls == ReadableMap.class) {
            return new l(aVar, method);
        }
        throw new RuntimeException("Unrecognized type: " + cls + " for method: " + method.getDeclaringClass().getName() + "#" + method.getName());
    }

    private static void d(K1.b bVar, Method method, Class cls, Map map) {
        String[] strArrNames = bVar.names();
        int i3 = 0;
        if (cls == Dynamic.class) {
            while (i3 < strArrNames.length) {
                map.put(strArrNames[i3], new i(bVar, method, i3));
                i3++;
            }
            return;
        }
        if (cls == Integer.TYPE) {
            while (i3 < strArrNames.length) {
                if ("Color".equals(bVar.customType())) {
                    map.put(strArrNames[i3], new g(bVar, method, i3, bVar.defaultInt()));
                } else {
                    map.put(strArrNames[i3], new k(bVar, method, i3, bVar.defaultInt()));
                }
                i3++;
            }
            return;
        }
        if (cls == Float.TYPE) {
            while (i3 < strArrNames.length) {
                map.put(strArrNames[i3], new j(bVar, method, i3, bVar.defaultFloat()));
                i3++;
            }
            return;
        }
        if (cls == Double.TYPE) {
            while (i3 < strArrNames.length) {
                map.put(strArrNames[i3], new h(bVar, method, i3, bVar.defaultDouble()));
                i3++;
            }
            return;
        }
        if (cls == Integer.class) {
            while (i3 < strArrNames.length) {
                if ("Color".equals(bVar.customType())) {
                    map.put(strArrNames[i3], new e(bVar, method, i3));
                } else {
                    map.put(strArrNames[i3], new f(bVar, method, i3));
                }
                i3++;
            }
            return;
        }
        throw new RuntimeException("Unrecognized type: " + cls + " for method: " + method.getDeclaringClass().getName() + "#" + method.getName());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static ThreadLocal e(int i3) {
        if (i3 <= 0) {
            return null;
        }
        return new a(i3);
    }

    private static void f(Class cls, Map map) {
        for (Method method : cls.getDeclaredMethods()) {
            K1.a aVar = (K1.a) method.getAnnotation(K1.a.class);
            if (aVar != null) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length != 1) {
                    throw new RuntimeException("Wrong number of args for prop setter: " + cls.getName() + "#" + method.getName());
                }
                map.put(aVar.name(), c(aVar, method, parameterTypes[0]));
            }
            K1.b bVar = (K1.b) method.getAnnotation(K1.b.class);
            if (bVar != null) {
                Class<?>[] parameterTypes2 = method.getParameterTypes();
                if (parameterTypes2.length != 2) {
                    throw new RuntimeException("Wrong number of args for group prop setter: " + cls.getName() + "#" + method.getName());
                }
                if (parameterTypes2[0] != Integer.TYPE) {
                    throw new RuntimeException("Second argument should be property index: " + cls.getName() + "#" + method.getName());
                }
                d(bVar, method, parameterTypes2[1], map);
            }
        }
    }

    private static void g(Class cls, Map map) {
        for (Method method : cls.getDeclaredMethods()) {
            K1.a aVar = (K1.a) method.getAnnotation(K1.a.class);
            if (aVar != null) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length != 2) {
                    throw new RuntimeException("Wrong number of args for prop setter: " + cls.getName() + "#" + method.getName());
                }
                if (!View.class.isAssignableFrom(parameterTypes[0])) {
                    throw new RuntimeException("First param should be a view subclass to be updated: " + cls.getName() + "#" + method.getName());
                }
                map.put(aVar.name(), c(aVar, method, parameterTypes[1]));
            }
            K1.b bVar = (K1.b) method.getAnnotation(K1.b.class);
            if (bVar != null) {
                Class<?>[] parameterTypes2 = method.getParameterTypes();
                if (parameterTypes2.length != 3) {
                    throw new RuntimeException("Wrong number of args for group prop setter: " + cls.getName() + "#" + method.getName());
                }
                if (!View.class.isAssignableFrom(parameterTypes2[0])) {
                    throw new RuntimeException("First param should be a view subclass to be updated: " + cls.getName() + "#" + method.getName());
                }
                if (parameterTypes2[1] != Integer.TYPE) {
                    throw new RuntimeException("Second argument should be property index: " + cls.getName() + "#" + method.getName());
                }
                d(bVar, method, parameterTypes2[2], map);
            }
        }
    }

    static Map h(Class cls) {
        if (cls == null) {
            return f7540b;
        }
        for (Class<?> cls2 : cls.getInterfaces()) {
            if (cls2 == InterfaceC0466q0.class) {
                return f7540b;
            }
        }
        Map map = f7539a;
        Map map2 = (Map) map.get(cls);
        if (map2 != null) {
            return map2;
        }
        HashMap map3 = new HashMap(h(cls.getSuperclass()));
        f(cls, map3);
        map.put(cls, map3);
        return map3;
    }

    static Map i(Class cls) {
        if (cls == ViewManager.class) {
            return f7540b;
        }
        Map map = f7539a;
        Map map2 = (Map) map.get(cls);
        if (map2 != null) {
            return map2;
        }
        HashMap map3 = new HashMap(i(cls.getSuperclass()));
        g(cls, map3);
        map.put(cls, map3);
        return map3;
    }

    private static class g extends m {

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final int f7543i;

        public g(K1.a aVar, Method method, int i3) {
            super(aVar, "mixed", method);
            this.f7543i = i3;
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return obj == null ? Integer.valueOf(this.f7543i) : ColorPropConverter.getColor(obj, context);
        }

        public g(K1.b bVar, Method method, int i3, int i4) {
            super(bVar, "mixed", method, i3);
            this.f7543i = i4;
        }
    }

    private static class h extends m {

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final double f7544i;

        public h(K1.a aVar, Method method, double d3) {
            super(aVar, "number", method);
            this.f7544i = d3;
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return Double.valueOf(obj == null ? this.f7544i : ((Double) obj).doubleValue());
        }

        public h(K1.b bVar, Method method, int i3, double d3) {
            super(bVar, "number", method, i3);
            this.f7544i = d3;
        }
    }

    private static class j extends m {

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final float f7545i;

        public j(K1.a aVar, Method method, float f3) {
            super(aVar, "number", method);
            this.f7545i = f3;
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return Float.valueOf(obj == null ? this.f7545i : ((Double) obj).floatValue());
        }

        public j(K1.b bVar, Method method, int i3, float f3) {
            super(bVar, "number", method, i3);
            this.f7545i = f3;
        }
    }

    private static class k extends m {

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final int f7546i;

        public k(K1.a aVar, Method method, int i3) {
            super(aVar, "number", method);
            this.f7546i = i3;
        }

        @Override // com.facebook.react.uimanager.X0.m
        protected Object c(Object obj, Context context) {
            return Integer.valueOf(obj == null ? this.f7546i : ((Double) obj).intValue());
        }

        public k(K1.b bVar, Method method, int i3, int i4) {
            super(bVar, "number", method, i3);
            this.f7546i = i4;
        }
    }

    static abstract class m {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private static final ThreadLocal f7547e = X0.e(2);

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private static final ThreadLocal f7548f = X0.e(3);

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private static final ThreadLocal f7549g = X0.e(1);

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private static final ThreadLocal f7550h = X0.e(2);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        protected final String f7551a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        protected final String f7552b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        protected final Method f7553c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        protected final Integer f7554d;

        public String a() {
            return this.f7551a;
        }

        public String b() {
            return this.f7552b;
        }

        protected abstract Object c(Object obj, Context context);

        public void d(InterfaceC0466q0 interfaceC0466q0, Object obj) {
            Object[] objArr;
            try {
                if (this.f7554d == null) {
                    objArr = (Object[]) f7549g.get();
                    objArr[0] = c(obj, interfaceC0466q0.l());
                } else {
                    objArr = (Object[]) f7550h.get();
                    objArr[0] = this.f7554d;
                    objArr[1] = c(obj, interfaceC0466q0.l());
                }
                this.f7553c.invoke(interfaceC0466q0, objArr);
                Arrays.fill(objArr, (Object) null);
            } catch (Throwable th) {
                Y.a.j(ViewManager.class, "Error while updating prop " + this.f7551a, th);
                throw new JSApplicationIllegalArgumentException("Error while updating property '" + this.f7551a + "' in shadow node of type: " + interfaceC0466q0.v(), th);
            }
        }

        public void e(ViewManager viewManager, View view, Object obj) {
            Object[] objArr;
            try {
                if (this.f7554d == null) {
                    objArr = (Object[]) f7547e.get();
                    objArr[0] = view;
                    objArr[1] = c(obj, view.getContext());
                } else {
                    objArr = (Object[]) f7548f.get();
                    objArr[0] = view;
                    objArr[1] = this.f7554d;
                    objArr[2] = c(obj, view.getContext());
                }
                this.f7553c.invoke(viewManager, objArr);
                Arrays.fill(objArr, (Object) null);
            } catch (Throwable th) {
                Y.a.j(ViewManager.class, "Error while updating prop " + this.f7551a, th);
                throw new JSApplicationIllegalArgumentException("Error while updating property '" + this.f7551a + "' of a view managed by: " + viewManager.getName(), th);
            }
        }

        private m(K1.a aVar, String str, Method method) {
            this.f7551a = aVar.name();
            this.f7552b = "__default_type__".equals(aVar.customType()) ? str : aVar.customType();
            this.f7553c = method;
            this.f7554d = null;
        }

        private m(K1.b bVar, String str, Method method, int i3) {
            this.f7551a = bVar.names()[i3];
            this.f7552b = "__default_type__".equals(bVar.customType()) ? str : bVar.customType();
            this.f7553c = method;
            this.f7554d = Integer.valueOf(i3);
        }
    }
}
