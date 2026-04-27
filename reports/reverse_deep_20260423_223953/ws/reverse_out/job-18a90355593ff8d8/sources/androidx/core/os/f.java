package androidx.core.os;

import android.os.Build;
import android.os.Trace;
import android.util.Log;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes.dex */
public abstract class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static long f4372a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static Method f4373b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static Method f4374c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static Method f4375d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static Method f4376e;

    static {
        if (Build.VERSION.SDK_INT < 29) {
            try {
                f4372a = Trace.class.getField("TRACE_TAG_APP").getLong(null);
                Class cls = Long.TYPE;
                f4373b = Trace.class.getMethod("isTagEnabled", cls);
                Class cls2 = Integer.TYPE;
                f4374c = Trace.class.getMethod("asyncTraceBegin", cls, String.class, cls2);
                f4375d = Trace.class.getMethod("asyncTraceEnd", cls, String.class, cls2);
                f4376e = Trace.class.getMethod("traceCounter", cls, String.class, cls2);
            } catch (Exception e3) {
                Log.i("TraceCompat", "Unable to initialize via reflection.", e3);
            }
        }
    }

    public static void a(String str) {
        Trace.beginSection(str);
    }

    public static void b() {
        Trace.endSection();
    }
}
