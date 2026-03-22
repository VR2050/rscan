package com.alipay.apmobilesecuritysdk.p391d;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.p392e.C3184h;
import java.util.HashMap;
import java.util.Map;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.d.b */
/* loaded from: classes.dex */
public final class C3173b {
    /* renamed from: a */
    public static synchronized Map<String, String> m3745a(Context context, Map<String, String> map) {
        HashMap hashMap;
        synchronized (C3173b.class) {
            hashMap = new HashMap();
            String m4808h = C4195m.m4808h(map, "tid", "");
            String m4808h2 = C4195m.m4808h(map, "utdid", "");
            String m4808h3 = C4195m.m4808h(map, "userId", "");
            String m4808h4 = C4195m.m4808h(map, "appName", "");
            String m4808h5 = C4195m.m4808h(map, "appKeyClient", "");
            String m4808h6 = C4195m.m4808h(map, "tmxSessionId", "");
            String m3796f = C3184h.m3796f(context);
            String m4808h7 = C4195m.m4808h(map, "sessionId", "");
            hashMap.put("AC1", m4808h);
            hashMap.put("AC2", m4808h2);
            hashMap.put("AC3", "");
            hashMap.put("AC4", m3796f);
            hashMap.put("AC5", m4808h3);
            hashMap.put("AC6", m4808h6);
            hashMap.put("AC7", "");
            hashMap.put("AC8", m4808h4);
            hashMap.put("AC9", m4808h5);
            if (C4195m.m4840x(m4808h7)) {
                hashMap.put("AC10", m4808h7);
            }
        }
        return hashMap;
    }
}
