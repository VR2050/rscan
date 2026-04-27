package I;

import android.os.Build;
import android.os.Trace;
import android.util.Log;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes.dex */
public abstract class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static long f1098a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static Method f1099b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static Method f1100c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static Method f1101d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static Method f1102e;

    public static void a(String str, int i3) {
        if (Build.VERSION.SDK_INT >= 29) {
            c.a(str, i3);
        } else {
            b(str, i3);
        }
    }

    private static void b(String str, int i3) {
        try {
            if (f1100c == null) {
                f1100c = Trace.class.getMethod("asyncTraceBegin", Long.TYPE, String.class, Integer.TYPE);
            }
            f1100c.invoke(null, Long.valueOf(f1098a), str, Integer.valueOf(i3));
        } catch (Exception e3) {
            g("asyncTraceBegin", e3);
        }
    }

    public static void c(String str) {
        b.a(str);
    }

    public static void d(String str, int i3) {
        if (Build.VERSION.SDK_INT >= 29) {
            c.b(str, i3);
        } else {
            e(str, i3);
        }
    }

    private static void e(String str, int i3) {
        try {
            if (f1101d == null) {
                f1101d = Trace.class.getMethod("asyncTraceEnd", Long.TYPE, String.class, Integer.TYPE);
            }
            f1101d.invoke(null, Long.valueOf(f1098a), str, Integer.valueOf(i3));
        } catch (Exception e3) {
            g("asyncTraceEnd", e3);
        }
    }

    public static void f() {
        b.b();
    }

    private static void g(String str, Exception exc) {
        if (exc instanceof InvocationTargetException) {
            Throwable cause = exc.getCause();
            if (!(cause instanceof RuntimeException)) {
                throw new RuntimeException(cause);
            }
            throw ((RuntimeException) cause);
        }
        Log.v("Trace", "Unable to call " + str + " via reflection", exc);
    }

    public static boolean h() {
        return Build.VERSION.SDK_INT >= 29 ? c.c() : i();
    }

    private static boolean i() {
        try {
            if (f1099b == null) {
                f1098a = Trace.class.getField("TRACE_TAG_APP").getLong(null);
                f1099b = Trace.class.getMethod("isTagEnabled", Long.TYPE);
            }
            return ((Boolean) f1099b.invoke(null, Long.valueOf(f1098a))).booleanValue();
        } catch (Exception e3) {
            g("isTagEnabled", e3);
            return false;
        }
    }

    public static void j(String str, int i3) {
        if (Build.VERSION.SDK_INT >= 29) {
            c.d(str, i3);
        } else {
            k(str, i3);
        }
    }

    private static void k(String str, int i3) {
        try {
            if (f1102e == null) {
                f1102e = Trace.class.getMethod("traceCounter", Long.TYPE, String.class, Integer.TYPE);
            }
            f1102e.invoke(null, Long.valueOf(f1098a), str, Integer.valueOf(i3));
        } catch (Exception e3) {
            g("traceCounter", e3);
        }
    }
}
