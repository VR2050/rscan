package com.alipay.mobilesecuritysdk.face;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.face.APSecuritySdk;
import com.alipay.apmobilesecuritysdk.p388a.C3167a;
import java.util.HashMap;
import java.util.Map;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class SecurityClientMobile {
    public static synchronized String GetApdid(Context context, Map<String, String> map) {
        String m3727a;
        synchronized (SecurityClientMobile.class) {
            HashMap hashMap = new HashMap();
            hashMap.put("utdid", C4195m.m4808h(map, "utdid", ""));
            hashMap.put("tid", C4195m.m4808h(map, "tid", ""));
            hashMap.put("userId", C4195m.m4808h(map, "userId", ""));
            APSecuritySdk.getInstance(context).initToken(0, hashMap, null);
            m3727a = C3167a.m3727a(context);
        }
        return m3727a;
    }
}
