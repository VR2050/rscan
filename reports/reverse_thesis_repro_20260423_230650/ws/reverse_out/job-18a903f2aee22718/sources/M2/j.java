package M2;

import java.lang.reflect.Method;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class j {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f1826d = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Method f1827a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Method f1828b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Method f1829c;

    public static final class a {
        private a() {
        }

        public final j a() {
            Method method;
            Method method2;
            Method method3;
            try {
                Class<?> cls = Class.forName("dalvik.system.CloseGuard");
                method = cls.getMethod("get", new Class[0]);
                method3 = cls.getMethod("open", String.class);
                method2 = cls.getMethod("warnIfOpen", new Class[0]);
            } catch (Exception unused) {
                method = null;
                method2 = null;
                method3 = null;
            }
            return new j(method, method3, method2);
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public j(Method method, Method method2, Method method3) {
        this.f1827a = method;
        this.f1828b = method2;
        this.f1829c = method3;
    }

    public final Object a(String str) {
        t2.j.f(str, "closer");
        Method method = this.f1827a;
        if (method != null) {
            try {
                Object objInvoke = method.invoke(null, new Object[0]);
                Method method2 = this.f1828b;
                t2.j.c(method2);
                method2.invoke(objInvoke, str);
                return objInvoke;
            } catch (Exception unused) {
            }
        }
        return null;
    }

    public final boolean b(Object obj) {
        if (obj == null) {
            return false;
        }
        try {
            Method method = this.f1829c;
            t2.j.c(method);
            method.invoke(obj, new Object[0]);
            return true;
        } catch (Exception unused) {
            return false;
        }
    }
}
