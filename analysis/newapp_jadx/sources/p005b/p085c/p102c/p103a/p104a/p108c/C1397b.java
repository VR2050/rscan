package p005b.p085c.p102c.p103a.p104a.p108c;

import android.content.Context;
import java.util.HashMap;
import p005b.p085c.p102c.p103a.p104a.p105a.p106a.C1392b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.c.b */
/* loaded from: classes.dex */
public final class C1397b {
    /* renamed from: a */
    public static synchronized void m478a(Context context, String str, String str2, String str3) {
        synchronized (C1397b.class) {
            if (!C4195m.m4822o(str)) {
                if (!C4195m.m4822o(str2) && context != null) {
                    try {
                        String m460b = C1392b.m460b(C1392b.m459a(), str3);
                        HashMap hashMap = new HashMap();
                        hashMap.put(str2, m460b);
                        C4195m.m4812j(context, str, hashMap);
                    } catch (Throwable unused) {
                    }
                }
            }
        }
    }
}
