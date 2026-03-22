package com.alipay.apmobilesecuritysdk.p392e;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.UUID;
import p005b.p085c.p102c.p103a.p104a.p108c.C1396a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.e.h */
/* loaded from: classes.dex */
public class C3184h {

    /* renamed from: a */
    private static String f8631a = "";

    /* renamed from: a */
    public static long m3783a(Context context) {
        String m476a = C1396a.m476a(context, "vkeyid_settings", "update_time_interval");
        if (!C4195m.m4840x(m476a)) {
            return 86400000L;
        }
        try {
            return Long.parseLong(m476a);
        } catch (Exception unused) {
            return 86400000L;
        }
    }

    /* renamed from: a */
    public static void m3784a(Context context, String str) {
        m3786a(context, "update_time_interval", str);
    }

    /* renamed from: a */
    public static void m3785a(Context context, String str, long j2) {
        C1396a.m477b(context, "vkeyid_settings", "vkey_valid" + str, String.valueOf(j2));
    }

    /* renamed from: a */
    private static void m3786a(Context context, String str, String str2) {
        C1396a.m477b(context, "vkeyid_settings", str, str2);
    }

    /* renamed from: a */
    public static void m3787a(Context context, boolean z) {
        m3786a(context, "log_switch", z ? "1" : "0");
    }

    /* renamed from: b */
    public static String m3788b(Context context) {
        return C1396a.m476a(context, "vkeyid_settings", "last_apdid_env");
    }

    /* renamed from: b */
    public static void m3789b(Context context, String str) {
        m3786a(context, "last_machine_boot_time", str);
    }

    /* renamed from: c */
    public static void m3790c(Context context, String str) {
        m3786a(context, "last_apdid_env", str);
    }

    /* renamed from: c */
    public static boolean m3791c(Context context) {
        String m476a = C1396a.m476a(context, "vkeyid_settings", "log_switch");
        return m476a != null && "1".equals(m476a);
    }

    /* renamed from: d */
    public static String m3792d(Context context) {
        return C1396a.m476a(context, "vkeyid_settings", "dynamic_key");
    }

    /* renamed from: d */
    public static void m3793d(Context context, String str) {
        m3786a(context, "agent_switch", str);
    }

    /* renamed from: e */
    public static String m3794e(Context context) {
        return C1396a.m476a(context, "vkeyid_settings", "apse_degrade");
    }

    /* renamed from: e */
    public static void m3795e(Context context, String str) {
        m3786a(context, "dynamic_key", str);
    }

    /* renamed from: f */
    public static String m3796f(Context context) {
        String str;
        SharedPreferences.Editor edit;
        synchronized (C3184h.class) {
            if (C4195m.m4822o(f8631a)) {
                String string = context.getSharedPreferences("alipay_vkey_random", 0).getString("random", "");
                f8631a = string;
                if (C4195m.m4822o(string)) {
                    String m4830s = C4195m.m4830s(UUID.randomUUID().toString());
                    f8631a = m4830s;
                    if (m4830s != null && (edit = context.getSharedPreferences("alipay_vkey_random", 0).edit()) != null) {
                        edit.putString("random", m4830s);
                        edit.commit();
                    }
                }
            }
            str = f8631a;
        }
        return str;
    }

    /* renamed from: f */
    public static void m3797f(Context context, String str) {
        m3786a(context, "webrtc_url", str);
    }

    /* renamed from: g */
    public static void m3798g(Context context, String str) {
        m3786a(context, "apse_degrade", str);
    }

    /* renamed from: h */
    public static long m3799h(Context context, String str) {
        try {
            String m476a = C1396a.m476a(context, "vkeyid_settings", "vkey_valid" + str);
            if (C4195m.m4822o(m476a)) {
                return 0L;
            }
            return Long.parseLong(m476a);
        } catch (Throwable unused) {
            return 0L;
        }
    }
}
