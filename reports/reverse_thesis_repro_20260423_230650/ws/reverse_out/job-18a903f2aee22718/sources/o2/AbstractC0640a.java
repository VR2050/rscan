package o2;

import java.lang.reflect.InvocationTargetException;
import n2.AbstractC0635a;
import t2.j;

/* JADX INFO: renamed from: o2.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0640a extends AbstractC0635a {

    /* JADX INFO: renamed from: o2.a$a, reason: collision with other inner class name */
    private static final class C0142a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final C0142a f9725a = new C0142a();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final Integer f9726b;

        static {
            Object obj;
            Integer num = null;
            try {
                obj = Class.forName("android.os.Build$VERSION").getField("SDK_INT").get(null);
            } catch (Throwable unused) {
            }
            Integer num2 = obj instanceof Integer ? (Integer) obj : null;
            if (num2 != null && num2.intValue() > 0) {
                num = num2;
            }
            f9726b = num;
        }

        private C0142a() {
        }
    }

    private final boolean b(int i3) {
        Integer num = C0142a.f9726b;
        return num == null || num.intValue() >= i3;
    }

    @Override // n2.AbstractC0635a
    public void a(Throwable th, Throwable th2) throws IllegalAccessException, InvocationTargetException {
        j.f(th, "cause");
        j.f(th2, "exception");
        if (b(19)) {
            th.addSuppressed(th2);
        } else {
            super.a(th, th2);
        }
    }
}
