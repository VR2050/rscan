package com.alipay.apmobilesecuritysdk.p392e;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.p390c.C3169a;
import com.alipay.apmobilesecuritysdk.p393f.C3186a;
import org.json.JSONObject;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.e.a */
/* loaded from: classes.dex */
public final class C3177a {
    /* renamed from: a */
    private static C3178b m3754a(String str) {
        try {
            if (C4195m.m4822o(str)) {
                return null;
            }
            JSONObject jSONObject = new JSONObject(str);
            return new C3178b(jSONObject.optString("apdid"), jSONObject.optString("deviceInfoHash"), jSONObject.optString("timestamp"));
        } catch (Exception e2) {
            C3169a.m3740a(e2);
            return null;
        }
    }

    /* renamed from: a */
    public static synchronized void m3755a() {
        synchronized (C3177a.class) {
        }
    }

    /* renamed from: a */
    public static synchronized void m3756a(Context context) {
        synchronized (C3177a.class) {
            C3186a.m3820a(context, "vkeyid_profiles_v3", "deviceid", "");
            C3186a.m3821a("wxcasxx_v3", "wxcasxx", "");
        }
    }

    /* renamed from: a */
    public static synchronized void m3757a(Context context, C3178b c3178b) {
        synchronized (C3177a.class) {
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("apdid", c3178b.f8618a);
                jSONObject.put("deviceInfoHash", c3178b.f8619b);
                jSONObject.put("timestamp", c3178b.f8620c);
                String jSONObject2 = jSONObject.toString();
                C3186a.m3820a(context, "vkeyid_profiles_v3", "deviceid", jSONObject2);
                C3186a.m3821a("wxcasxx_v3", "wxcasxx", jSONObject2);
            } catch (Exception e2) {
                C3169a.m3740a(e2);
            }
        }
    }

    /* renamed from: b */
    public static synchronized C3178b m3758b() {
        synchronized (C3177a.class) {
            String m3819a = C3186a.m3819a("wxcasxx_v3", "wxcasxx");
            if (C4195m.m4822o(m3819a)) {
                return null;
            }
            return m3754a(m3819a);
        }
    }

    /* renamed from: b */
    public static synchronized C3178b m3759b(Context context) {
        C3178b m3754a;
        synchronized (C3177a.class) {
            String m3818a = C3186a.m3818a(context, "vkeyid_profiles_v3", "deviceid");
            if (C4195m.m4822o(m3818a)) {
                m3818a = C3186a.m3819a("wxcasxx_v3", "wxcasxx");
            }
            m3754a = m3754a(m3818a);
        }
        return m3754a;
    }

    /* renamed from: c */
    public static synchronized C3178b m3760c(Context context) {
        synchronized (C3177a.class) {
            String m3818a = C3186a.m3818a(context, "vkeyid_profiles_v3", "deviceid");
            if (C4195m.m4822o(m3818a)) {
                return null;
            }
            return m3754a(m3818a);
        }
    }
}
