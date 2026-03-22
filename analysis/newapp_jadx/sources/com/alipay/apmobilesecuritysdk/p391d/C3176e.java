package com.alipay.apmobilesecuritysdk.p391d;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.d.e */
/* loaded from: classes.dex */
public final class C3176e {

    /* renamed from: a */
    private static Map<String, String> f8616a;

    /* renamed from: b */
    private static final String[] f8617b = {"AD1", "AD2", "AD3", "AD8", "AD9", "AD10", "AD11", "AD12", "AD14", "AD15", "AD16", "AD18", "AD20", "AD21", "AD23", "AD24", "AD26", "AD27", "AD28", "AD29", "AD30", "AD31", "AD34", "AA1", "AA2", "AA3", "AA4", "AC4", "AC10", "AE1", "AE2", "AE3", "AE4", "AE5", "AE6", "AE7", "AE8", "AE9", "AE10", "AE11", "AE12", "AE13", "AE14", "AE15"};

    /* renamed from: a */
    private static String m3749a(Map<String, String> map) {
        StringBuffer stringBuffer = new StringBuffer();
        ArrayList arrayList = new ArrayList(map.keySet());
        Collections.sort(arrayList);
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            String str = (String) arrayList.get(i2);
            String str2 = map.get(str);
            String str3 = "";
            if (str2 == null) {
                str2 = "";
            }
            StringBuilder sb = new StringBuilder();
            if (i2 != 0) {
                str3 = "&";
            }
            sb.append(str3);
            sb.append(str);
            sb.append("=");
            sb.append(str2);
            stringBuffer.append(sb.toString());
        }
        return stringBuffer.toString();
    }

    /* renamed from: a */
    public static synchronized Map<String, String> m3750a(Context context, Map<String, String> map) {
        Map<String, String> map2;
        synchronized (C3176e.class) {
            if (f8616a == null) {
                m3753c(context, map);
            }
            f8616a.putAll(C3175d.m3747a());
            map2 = f8616a;
        }
        return map2;
    }

    /* renamed from: a */
    public static synchronized void m3751a() {
        synchronized (C3176e.class) {
            f8616a = null;
        }
    }

    /* renamed from: b */
    public static synchronized String m3752b(Context context, Map<String, String> map) {
        String m4830s;
        synchronized (C3176e.class) {
            m3750a(context, map);
            TreeMap treeMap = new TreeMap();
            for (String str : f8617b) {
                if (f8616a.containsKey(str)) {
                    treeMap.put(str, f8616a.get(str));
                }
            }
            m4830s = C4195m.m4830s(m3749a(treeMap));
        }
        return m4830s;
    }

    /* renamed from: c */
    private static synchronized void m3753c(Context context, Map<String, String> map) {
        synchronized (C3176e.class) {
            TreeMap treeMap = new TreeMap();
            f8616a = treeMap;
            treeMap.putAll(C3173b.m3745a(context, map));
            f8616a.putAll(C3175d.m3748a(context));
            f8616a.putAll(C3174c.m3746a(context));
            f8616a.putAll(C3172a.m3744a(context, map));
        }
    }
}
