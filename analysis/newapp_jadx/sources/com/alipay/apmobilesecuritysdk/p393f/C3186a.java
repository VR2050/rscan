package com.alipay.apmobilesecuritysdk.p393f;

import android.content.Context;
import android.os.Environment;
import java.io.File;
import java.util.HashMap;
import org.json.JSONObject;
import p005b.p085c.p102c.p103a.p104a.p105a.p106a.C1392b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.f.a */
/* loaded from: classes.dex */
public class C3186a {
    /* renamed from: a */
    public static String m3818a(Context context, String str, String str2) {
        if (context == null || C4195m.m4822o(str) || C4195m.m4822o(str2)) {
            return null;
        }
        try {
            String string = context.getSharedPreferences(str, 0).getString(str2, "");
            if (C4195m.m4822o(string)) {
                return null;
            }
            return C1392b.m462d(C1392b.m459a(), string);
        } catch (Throwable unused) {
            return null;
        }
    }

    /* renamed from: a */
    public static String m3819a(String str, String str2) {
        synchronized (C3186a.class) {
            if (C4195m.m4822o(str) || C4195m.m4822o(str2)) {
                return null;
            }
            try {
                String m4832t = C4195m.m4832t(str);
                if (C4195m.m4822o(m4832t)) {
                    return null;
                }
                String string = new JSONObject(m4832t).getString(str2);
                if (C4195m.m4822o(string)) {
                    return null;
                }
                return C1392b.m462d(C1392b.m459a(), string);
            } catch (Throwable unused) {
                return null;
            }
        }
    }

    /* renamed from: a */
    public static void m3820a(Context context, String str, String str2, String str3) {
        if (C4195m.m4822o(str) || C4195m.m4822o(str2) || context == null) {
            return;
        }
        try {
            String m460b = C1392b.m460b(C1392b.m459a(), str3);
            HashMap hashMap = new HashMap();
            hashMap.put(str2, m460b);
            C4195m.m4812j(context, str, hashMap);
        } catch (Throwable unused) {
        }
    }

    /* renamed from: a */
    public static void m3821a(String str, String str2, String str3) {
        synchronized (C3186a.class) {
            if (C4195m.m4822o(str) || C4195m.m4822o(str2)) {
                return;
            }
            try {
                String m4832t = C4195m.m4832t(str);
                JSONObject jSONObject = new JSONObject();
                if (C4195m.m4840x(m4832t)) {
                    try {
                        jSONObject = new JSONObject(m4832t);
                    } catch (Exception unused) {
                        jSONObject = new JSONObject();
                    }
                }
                jSONObject.put(str2, C1392b.m460b(C1392b.m459a(), str3));
                jSONObject.toString();
                try {
                    System.clearProperty(str);
                } catch (Throwable unused2) {
                }
                if (C4195m.m4818m()) {
                    String str4 = ".SystemConfig" + File.separator + str;
                    if (C4195m.m4818m()) {
                        File file = new File(Environment.getExternalStorageDirectory(), str4);
                        if (file.exists() && file.isFile()) {
                            file.delete();
                        }
                    }
                }
            } catch (Throwable unused3) {
            }
        }
    }
}
