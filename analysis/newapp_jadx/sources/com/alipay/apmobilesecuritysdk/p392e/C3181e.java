package com.alipay.apmobilesecuritysdk.p392e;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.p390c.C3169a;
import com.alipay.apmobilesecuritysdk.p393f.C3186a;
import org.json.JSONObject;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.e.e */
/* loaded from: classes.dex */
public final class C3181e {
    /* renamed from: a */
    public static C3182f m3768a(Context context) {
        if (context == null) {
            return null;
        }
        String m3818a = C3186a.m3818a(context, "device_feature_prefs_name", "device_feature_prefs_key");
        if (C4195m.m4822o(m3818a)) {
            m3818a = C3186a.m3819a("device_feature_file_name", "device_feature_file_key");
        }
        if (C4195m.m4822o(m3818a)) {
            return null;
        }
        try {
            JSONObject jSONObject = new JSONObject(m3818a);
            C3182f c3182f = new C3182f();
            c3182f.m3770a(jSONObject.getString("imei"));
            c3182f.m3772b(jSONObject.getString("imsi"));
            c3182f.m3774c(jSONObject.getString("mac"));
            c3182f.m3776d(jSONObject.getString("bluetoothmac"));
            c3182f.m3778e(jSONObject.getString("gsi"));
            return c3182f;
        } catch (Exception e2) {
            C3169a.m3740a(e2);
            return null;
        }
    }
}
