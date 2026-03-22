package com.p397ta.utdid2.device;

import com.p397ta.utdid2.p398a.p399a.C4130a;
import com.p397ta.utdid2.p398a.p399a.C4131b;
import com.p397ta.utdid2.p398a.p399a.C4136g;

/* renamed from: com.ta.utdid2.device.e */
/* loaded from: classes2.dex */
public class C4147e {
    /* renamed from: d */
    public String m4741d(String str) {
        return C4130a.m4645b(str);
    }

    /* renamed from: e */
    public String m4742e(String str) {
        String m4645b = C4130a.m4645b(str);
        if (!C4136g.m4661a(m4645b)) {
            try {
                return new String(C4131b.decode(m4645b, 0));
            } catch (IllegalArgumentException unused) {
            }
        }
        return null;
    }
}
