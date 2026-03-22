package tv.danmaku.ijk.media.player.pragma;

import java.util.Locale;

/* loaded from: classes3.dex */
public class DebugLog {
    public static final boolean ENABLE_DEBUG = true;
    public static final boolean ENABLE_ERROR = true;
    public static final boolean ENABLE_INFO = true;
    public static final boolean ENABLE_VERBOSE = true;
    public static final boolean ENABLE_WARN = true;

    /* renamed from: d */
    public static void m5714d(String str, String str2) {
    }

    /* renamed from: d */
    public static void m5715d(String str, String str2, Throwable th) {
    }

    public static void dfmt(String str, String str2, Object... objArr) {
        String.format(Locale.US, str2, objArr);
    }

    /* renamed from: e */
    public static void m5716e(String str, String str2) {
    }

    /* renamed from: e */
    public static void m5717e(String str, String str2, Throwable th) {
    }

    public static void efmt(String str, String str2, Object... objArr) {
        String.format(Locale.US, str2, objArr);
    }

    /* renamed from: i */
    public static void m5718i(String str, String str2) {
    }

    /* renamed from: i */
    public static void m5719i(String str, String str2, Throwable th) {
    }

    public static void ifmt(String str, String str2, Object... objArr) {
        String.format(Locale.US, str2, objArr);
    }

    public static void printCause(Throwable th) {
        Throwable cause = th.getCause();
        if (cause != null) {
            th = cause;
        }
        printStackTrace(th);
    }

    public static void printStackTrace(Throwable th) {
        th.printStackTrace();
    }

    /* renamed from: v */
    public static void m5720v(String str, String str2) {
    }

    /* renamed from: v */
    public static void m5721v(String str, String str2, Throwable th) {
    }

    public static void vfmt(String str, String str2, Object... objArr) {
        String.format(Locale.US, str2, objArr);
    }

    /* renamed from: w */
    public static void m5722w(String str, String str2) {
    }

    /* renamed from: w */
    public static void m5723w(String str, String str2, Throwable th) {
    }

    public static void wfmt(String str, String str2, Object... objArr) {
        String.format(Locale.US, str2, objArr);
    }
}
