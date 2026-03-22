package p476m.p496b.p497a;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p496b.p497a.p499s.InterfaceC4925a;

/* renamed from: m.b.a.p */
/* loaded from: classes3.dex */
public class C4922p {

    /* renamed from: a */
    public static final Map<Class<?>, List<C4921o>> f12559a = new ConcurrentHashMap();

    /* renamed from: b */
    public static final a[] f12560b = new a[4];

    /* renamed from: m.b.a.p$a */
    public static class a {

        /* renamed from: a */
        public final List<C4921o> f12561a = new ArrayList();

        /* renamed from: b */
        public final Map<Class, Object> f12562b = new HashMap();

        /* renamed from: c */
        public final Map<String, Class> f12563c = new HashMap();

        /* renamed from: d */
        public final StringBuilder f12564d = new StringBuilder(128);

        /* renamed from: e */
        public Class<?> f12565e;

        /* renamed from: f */
        public boolean f12566f;

        /* renamed from: g */
        public InterfaceC4925a f12567g;

        /* renamed from: a */
        public boolean m5591a(Method method, Class<?> cls) {
            Object put = this.f12562b.put(cls, method);
            if (put == null) {
                return true;
            }
            if (put instanceof Method) {
                if (!m5592b((Method) put, cls)) {
                    throw new IllegalStateException();
                }
                this.f12562b.put(cls, this);
            }
            return m5592b(method, cls);
        }

        /* renamed from: b */
        public final boolean m5592b(Method method, Class<?> cls) {
            this.f12564d.setLength(0);
            this.f12564d.append(method.getName());
            StringBuilder sb = this.f12564d;
            sb.append(Typography.greater);
            sb.append(cls.getName());
            String sb2 = this.f12564d.toString();
            Class<?> declaringClass = method.getDeclaringClass();
            Class put = this.f12563c.put(sb2, declaringClass);
            if (put == null || put.isAssignableFrom(declaringClass)) {
                return true;
            }
            this.f12563c.put(sb2, put);
            return false;
        }

        /* renamed from: c */
        public void m5593c() {
            if (this.f12566f) {
                this.f12565e = null;
                return;
            }
            Class<? super Object> superclass = this.f12565e.getSuperclass();
            this.f12565e = superclass;
            String name = superclass.getName();
            if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("android.") || name.startsWith("androidx.")) {
                this.f12565e = null;
            }
        }
    }

    public C4922p(List<?> list, boolean z, boolean z2) {
    }

    /* renamed from: a */
    public final void m5588a(a aVar) {
        Method[] methods;
        InterfaceC4919m interfaceC4919m;
        try {
            try {
                methods = aVar.f12565e.getDeclaredMethods();
            } catch (LinkageError e2) {
                throw new C4911e(C1499a.m637w(C1499a.m623j(aVar.f12565e, C1499a.m586H("Could not inspect methods of ")), ". Please make this class visible to EventBus annotation processor to avoid reflection."), e2);
            }
        } catch (Throwable unused) {
            methods = aVar.f12565e.getMethods();
            aVar.f12566f = true;
        }
        for (Method method : methods) {
            int modifiers = method.getModifiers();
            if ((modifiers & 1) != 0 && (modifiers & 5192) == 0) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length == 1 && (interfaceC4919m = (InterfaceC4919m) method.getAnnotation(InterfaceC4919m.class)) != null) {
                    Class<?> cls = parameterTypes[0];
                    if (aVar.m5591a(method, cls)) {
                        aVar.f12561a.add(new C4921o(method, cls, interfaceC4919m.threadMode(), interfaceC4919m.priority(), interfaceC4919m.sticky()));
                    }
                }
            }
        }
    }

    /* renamed from: b */
    public final List<C4921o> m5589b(a aVar) {
        ArrayList arrayList = new ArrayList(aVar.f12561a);
        aVar.f12561a.clear();
        aVar.f12562b.clear();
        aVar.f12563c.clear();
        int i2 = 0;
        aVar.f12564d.setLength(0);
        aVar.f12565e = null;
        aVar.f12566f = false;
        aVar.f12567g = null;
        synchronized (f12560b) {
            while (true) {
                if (i2 >= 4) {
                    break;
                }
                a[] aVarArr = f12560b;
                if (aVarArr[i2] == null) {
                    aVarArr[i2] = aVar;
                    break;
                }
                i2++;
            }
        }
        return arrayList;
    }

    /* renamed from: c */
    public final a m5590c() {
        synchronized (f12560b) {
            for (int i2 = 0; i2 < 4; i2++) {
                a[] aVarArr = f12560b;
                a aVar = aVarArr[i2];
                if (aVar != null) {
                    aVarArr[i2] = null;
                    return aVar;
                }
            }
            return new a();
        }
    }
}
