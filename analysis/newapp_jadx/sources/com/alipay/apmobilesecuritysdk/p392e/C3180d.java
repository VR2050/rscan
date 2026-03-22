package com.alipay.apmobilesecuritysdk.p392e;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.p390c.C3169a;
import com.alipay.apmobilesecuritysdk.p393f.C3186a;
import org.json.JSONObject;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.e.d */
/* loaded from: classes.dex */
public final class C3180d {
    /* renamed from: a */
    private static C3179c m3761a(String str) {
        try {
            if (C4195m.m4822o(str)) {
                return null;
            }
            JSONObject jSONObject = new JSONObject(str);
            return new C3179c(jSONObject.optString("apdid"), jSONObject.optString("deviceInfoHash"), jSONObject.optString("timestamp"), jSONObject.optString("tid"), jSONObject.optString("utdid"));
        } catch (Exception e2) {
            C3169a.m3740a(e2);
            return null;
        }
    }

    /* renamed from: a */
    public static synchronized void m3762a() {
        synchronized (C3180d.class) {
        }
    }

    /* renamed from: a */
    public static synchronized void m3763a(Context context) {
        synchronized (C3180d.class) {
            C3186a.m3820a(context, "vkeyid_profiles_v4", "key_deviceid_v4", "");
            C3186a.m3821a("wxcasxx_v4", "key_wxcasxx_v4", "");
        }
    }

    /* renamed from: a */
    public static synchronized void m3764a(Context context, C3179c c3179c) {
        synchronized (C3180d.class) {
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("apdid", c3179c.f8621a);
                jSONObject.put("deviceInfoHash", c3179c.f8622b);
                jSONObject.put("timestamp", c3179c.f8623c);
                jSONObject.put("tid", c3179c.f8624d);
                jSONObject.put("utdid", c3179c.f8625e);
                String jSONObject2 = jSONObject.toString();
                C3186a.m3820a(context, "vkeyid_profiles_v4", "key_deviceid_v4", jSONObject2);
                C3186a.m3821a("wxcasxx_v4", "key_wxcasxx_v4", jSONObject2);
            } catch (Exception e2) {
                C3169a.m3740a(e2);
            }
        }
    }

    /* renamed from: b */
    public static synchronized C3179c m3765b() {
        synchronized (C3180d.class) {
            String m3819a = C3186a.m3819a("wxcasxx_v4", "key_wxcasxx_v4");
            if (C4195m.m4822o(m3819a)) {
                return null;
            }
            return m3761a(m3819a);
        }
    }

    /* renamed from: b */
    public static synchronized C3179c m3766b(Context context) {
        C3179c m3761a;
        synchronized (C3180d.class) {
            String m3818a = C3186a.m3818a(context, "vkeyid_profiles_v4", "key_deviceid_v4");
            if (C4195m.m4822o(m3818a)) {
                m3818a = C3186a.m3819a("wxcasxx_v4", "key_wxcasxx_v4");
            }
            m3761a = m3761a(m3818a);
        }
        return m3761a;
    }

    /* renamed from: c */
    public static synchronized C3179c m3767c(Context context) {
        synchronized (C3180d.class) {
            String m3818a = C3186a.m3818a(context, "vkeyid_profiles_v4", "key_deviceid_v4");
            if (C4195m.m4822o(m3818a)) {
                return null;
            }
            return m3761a(m3818a);
        }
    }
}
