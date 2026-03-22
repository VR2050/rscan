package com.p397ta.utdid2.device;

import android.content.Context;
import com.p397ta.utdid2.p398a.p399a.C4134e;
import com.p397ta.utdid2.p398a.p399a.C4136g;
import java.util.zip.Adler32;

/* renamed from: com.ta.utdid2.device.b */
/* loaded from: classes2.dex */
public class C4144b {

    /* renamed from: a */
    private static C4143a f10849a;

    /* renamed from: d */
    public static final Object f10850d = new Object();

    /* renamed from: a */
    public static long m4721a(C4143a c4143a) {
        if (c4143a == null) {
            return 0L;
        }
        String format = String.format("%s%s%s%s%s", c4143a.m4720f(), c4143a.getDeviceId(), Long.valueOf(c4143a.m4712a()), c4143a.getImsi(), c4143a.m4718e());
        if (C4136g.m4661a(format)) {
            return 0L;
        }
        Adler32 adler32 = new Adler32();
        adler32.reset();
        adler32.update(format.getBytes());
        return adler32.getValue();
    }

    /* renamed from: b */
    public static synchronized C4143a m4723b(Context context) {
        synchronized (C4144b.class) {
            C4143a c4143a = f10849a;
            if (c4143a != null) {
                return c4143a;
            }
            if (context == null) {
                return null;
            }
            C4143a m4722a = m4722a(context);
            f10849a = m4722a;
            return m4722a;
        }
    }

    /* renamed from: a */
    private static C4143a m4722a(Context context) {
        if (context == null) {
            return null;
        }
        synchronized (f10850d) {
            String value = C4145c.m4724a(context).getValue();
            if (C4136g.m4661a(value)) {
                return null;
            }
            if (value.endsWith("\n")) {
                value = value.substring(0, value.length() - 1);
            }
            C4143a c4143a = new C4143a();
            long currentTimeMillis = System.currentTimeMillis();
            String m4652a = C4134e.m4652a(context);
            String m4656c = C4134e.m4656c(context);
            c4143a.m4717d(m4652a);
            c4143a.m4715b(m4652a);
            c4143a.m4714b(currentTimeMillis);
            c4143a.m4716c(m4656c);
            c4143a.m4719e(value);
            c4143a.m4713a(m4721a(c4143a));
            return c4143a;
        }
    }
}
