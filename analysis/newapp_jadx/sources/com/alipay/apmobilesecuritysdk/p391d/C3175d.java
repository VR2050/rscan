package com.alipay.apmobilesecuritysdk.p391d;

import android.content.Context;
import android.os.Build;
import com.alipay.apmobilesecuritysdk.p390c.C3170b;
import java.util.HashMap;
import java.util.Map;
import p005b.p085c.p102c.p103a.p104a.p107b.C1393a;
import p005b.p085c.p102c.p103a.p104a.p107b.C1395c;

/* renamed from: com.alipay.apmobilesecuritysdk.d.d */
/* loaded from: classes.dex */
public final class C3175d {
    /* renamed from: a */
    public static synchronized Map<String, String> m3747a() {
        HashMap hashMap;
        synchronized (C3175d.class) {
            hashMap = new HashMap();
            try {
                new C3170b();
                hashMap.put("AE16", "");
            } catch (Throwable unused) {
            }
        }
        return hashMap;
    }

    /* renamed from: a */
    public static synchronized Map<String, String> m3748a(Context context) {
        HashMap hashMap;
        synchronized (C3175d.class) {
            hashMap = new HashMap();
            hashMap.put("AE1", "android");
            StringBuilder sb = new StringBuilder();
            sb.append(C1395c.m474b() ? "1" : "0");
            hashMap.put("AE2", sb.toString());
            StringBuilder sb2 = new StringBuilder();
            sb2.append(C1395c.m473a(context) ? "1" : "0");
            hashMap.put("AE3", sb2.toString());
            hashMap.put("AE4", Build.BOARD);
            hashMap.put("AE5", Build.BRAND);
            hashMap.put("AE6", Build.DEVICE);
            hashMap.put("AE7", Build.DISPLAY);
            hashMap.put("AE8", Build.VERSION.INCREMENTAL);
            hashMap.put("AE9", Build.MANUFACTURER);
            hashMap.put("AE10", Build.MODEL);
            hashMap.put("AE11", Build.PRODUCT);
            hashMap.put("AE12", Build.VERSION.RELEASE);
            hashMap.put("AE13", Build.VERSION.SDK);
            hashMap.put("AE14", Build.TAGS);
            hashMap.put("AE15", C1395c.m475c());
            hashMap.put("AE21", C1393a.m467d());
        }
        return hashMap;
    }
}
