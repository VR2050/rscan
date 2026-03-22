package com.alipay.apmobilesecuritysdk.p391d;

import android.content.Context;
import java.util.HashMap;
import java.util.Map;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.d.a */
/* loaded from: classes.dex */
public final class C3172a {
    /* renamed from: a */
    public static synchronized Map<String, String> m3744a(Context context, Map<String, String> map) {
        HashMap hashMap;
        String str;
        synchronized (C3172a.class) {
            String m4808h = C4195m.m4808h(map, "appchannel", "");
            hashMap = new HashMap();
            hashMap.put("AA1", context.getPackageName());
            try {
                str = context.getPackageManager().getPackageInfo(context.getPackageName(), 16).versionName;
            } catch (Exception unused) {
                str = "0.0.0";
            }
            hashMap.put("AA2", str);
            hashMap.put("AA3", "APPSecuritySDK-ALIPAYSDK");
            hashMap.put("AA4", "3.4.0.201910161639");
            hashMap.put("AA6", m4808h);
        }
        return hashMap;
    }
}
