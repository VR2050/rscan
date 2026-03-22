package com.alipay.apmobilesecuritysdk.p392e;

import android.content.Context;
import android.content.SharedPreferences;
import p005b.p085c.p102c.p103a.p104a.p105a.p106a.C1392b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.e.g */
/* loaded from: classes.dex */
public final class C3183g {
    /* renamed from: a */
    public static synchronized String m3779a(Context context, String str) {
        synchronized (C3183g.class) {
            String string = context.getSharedPreferences("openapi_file_pri", 0).getString("openApi" + str, "");
            if (C4195m.m4822o(string)) {
                return "";
            }
            String m462d = C1392b.m462d(C1392b.m459a(), string);
            return C4195m.m4822o(m462d) ? "" : m462d;
        }
    }

    /* renamed from: a */
    public static synchronized void m3780a() {
        synchronized (C3183g.class) {
        }
    }

    /* renamed from: a */
    public static synchronized void m3781a(Context context) {
        synchronized (C3183g.class) {
            SharedPreferences.Editor edit = context.getSharedPreferences("openapi_file_pri", 0).edit();
            if (edit != null) {
                edit.clear();
                edit.commit();
            }
        }
    }

    /* renamed from: a */
    public static synchronized void m3782a(Context context, String str, String str2) {
        synchronized (C3183g.class) {
            try {
                SharedPreferences.Editor edit = context.getSharedPreferences("openapi_file_pri", 0).edit();
                if (edit != null) {
                    edit.putString("openApi" + str, C1392b.m460b(C1392b.m459a(), str2));
                    edit.commit();
                }
            } catch (Throwable unused) {
            }
        }
    }
}
