package com.alipay.apmobilesecuritysdk.p392e;

import android.content.Context;
import java.util.HashMap;
import java.util.Map;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.e.i */
/* loaded from: classes.dex */
public final class C3185i {

    /* renamed from: a */
    private static String f8632a = "";

    /* renamed from: b */
    private static String f8633b = "";

    /* renamed from: c */
    private static String f8634c = "";

    /* renamed from: d */
    private static String f8635d = "";

    /* renamed from: e */
    private static String f8636e = "";

    /* renamed from: f */
    private static Map<String, String> f8637f = new HashMap();

    /* renamed from: a */
    public static synchronized String m3800a(String str) {
        synchronized (C3185i.class) {
            String str2 = "apdidTokenCache" + str;
            if (f8637f.containsKey(str2)) {
                String str3 = f8637f.get(str2);
                if (C4195m.m4840x(str3)) {
                    return str3;
                }
            }
            return "";
        }
    }

    /* renamed from: a */
    public static synchronized void m3801a() {
        synchronized (C3185i.class) {
        }
    }

    /* renamed from: a */
    public static synchronized void m3802a(C3178b c3178b) {
        synchronized (C3185i.class) {
            if (c3178b != null) {
                f8632a = c3178b.f8618a;
                f8633b = c3178b.f8619b;
                f8634c = c3178b.f8620c;
            }
        }
    }

    /* renamed from: a */
    public static synchronized void m3803a(C3179c c3179c) {
        synchronized (C3185i.class) {
            if (c3179c != null) {
                f8632a = c3179c.f8621a;
                f8633b = c3179c.f8622b;
                f8635d = c3179c.f8624d;
                f8636e = c3179c.f8625e;
                f8634c = c3179c.f8623c;
            }
        }
    }

    /* renamed from: a */
    public static synchronized void m3804a(String str, String str2) {
        synchronized (C3185i.class) {
            String str3 = "apdidTokenCache" + str;
            if (f8637f.containsKey(str3)) {
                f8637f.remove(str3);
            }
            f8637f.put(str3, str2);
        }
    }

    /* renamed from: a */
    public static synchronized boolean m3805a(Context context, String str) {
        synchronized (C3185i.class) {
            long j2 = 86400000;
            try {
                long m3783a = C3184h.m3783a(context);
                if (m3783a >= 0) {
                    j2 = m3783a;
                }
            } catch (Throwable unused) {
            }
            try {
                if (Math.abs(System.currentTimeMillis() - C3184h.m3799h(context, str)) < j2) {
                    return true;
                }
            } finally {
                return false;
            }
            return false;
        }
    }

    /* renamed from: b */
    public static synchronized String m3806b() {
        String str;
        synchronized (C3185i.class) {
            str = f8632a;
        }
        return str;
    }

    /* renamed from: b */
    public static void m3807b(String str) {
        f8632a = str;
    }

    /* renamed from: c */
    public static synchronized String m3808c() {
        String str;
        synchronized (C3185i.class) {
            str = f8633b;
        }
        return str;
    }

    /* renamed from: c */
    public static void m3809c(String str) {
        f8633b = str;
    }

    /* renamed from: d */
    public static synchronized String m3810d() {
        String str;
        synchronized (C3185i.class) {
            str = f8635d;
        }
        return str;
    }

    /* renamed from: d */
    public static void m3811d(String str) {
        f8634c = str;
    }

    /* renamed from: e */
    public static synchronized String m3812e() {
        String str;
        synchronized (C3185i.class) {
            str = f8636e;
        }
        return str;
    }

    /* renamed from: e */
    public static void m3813e(String str) {
        f8635d = str;
    }

    /* renamed from: f */
    public static synchronized String m3814f() {
        String str;
        synchronized (C3185i.class) {
            str = f8634c;
        }
        return str;
    }

    /* renamed from: f */
    public static void m3815f(String str) {
        f8636e = str;
    }

    /* renamed from: g */
    public static synchronized C3179c m3816g() {
        C3179c c3179c;
        synchronized (C3185i.class) {
            c3179c = new C3179c(f8632a, f8633b, f8634c, f8635d, f8636e);
        }
        return c3179c;
    }

    /* renamed from: h */
    public static void m3817h() {
        f8637f.clear();
        f8632a = "";
        f8633b = "";
        f8635d = "";
        f8636e = "";
        f8634c = "";
    }
}
