package n2;

import i2.AbstractC0580h;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import t2.j;

/* JADX INFO: renamed from: n2.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0635a {

    /* JADX INFO: renamed from: n2.a$a, reason: collision with other inner class name */
    private static final class C0140a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final C0140a f9683a = new C0140a();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final Method f9684b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final Method f9685c;

        static {
            Method method;
            Method method2;
            Method[] methods = Throwable.class.getMethods();
            j.c(methods);
            int length = methods.length;
            int i3 = 0;
            int i4 = 0;
            while (true) {
                method = null;
                if (i4 >= length) {
                    method2 = null;
                    break;
                }
                method2 = methods[i4];
                if (j.b(method2.getName(), "addSuppressed")) {
                    Class<?>[] parameterTypes = method2.getParameterTypes();
                    j.e(parameterTypes, "getParameterTypes(...)");
                    if (j.b(AbstractC0580h.A(parameterTypes), Throwable.class)) {
                        break;
                    }
                }
                i4++;
            }
            f9684b = method2;
            int length2 = methods.length;
            while (true) {
                if (i3 >= length2) {
                    break;
                }
                Method method3 = methods[i3];
                if (j.b(method3.getName(), "getSuppressed")) {
                    method = method3;
                    break;
                }
                i3++;
            }
            f9685c = method;
        }

        private C0140a() {
        }
    }

    public void a(Throwable th, Throwable th2) throws IllegalAccessException, InvocationTargetException {
        j.f(th, "cause");
        j.f(th2, "exception");
        Method method = C0140a.f9684b;
        if (method != null) {
            method.invoke(th, th2);
        }
    }
}
