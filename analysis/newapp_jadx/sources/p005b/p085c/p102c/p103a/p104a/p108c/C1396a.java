package p005b.p085c.p102c.p103a.p104a.p108c;

import android.content.Context;
import java.util.HashMap;
import p005b.p085c.p102c.p103a.p104a.p105a.p106a.C1392b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.c.a */
/* loaded from: classes.dex */
public class C1396a {
    /* renamed from: a */
    public static String m476a(Context context, String str, String str2) {
        String string;
        synchronized (C1396a.class) {
            String str3 = null;
            if (context != null) {
                if (!C4195m.m4822o(str) && !C4195m.m4822o(str2)) {
                    try {
                        string = context.getSharedPreferences(str, 0).getString(str2, "");
                    } catch (Throwable unused) {
                    }
                    if (C4195m.m4822o(string)) {
                        return null;
                    }
                    str3 = C1392b.m462d(C1392b.m459a(), string);
                    return str3;
                }
            }
            return null;
        }
    }

    /* renamed from: b */
    public static void m477b(Context context, String str, String str2, String str3) {
        synchronized (C1396a.class) {
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
    }
}
