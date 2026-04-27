package com.ta.utdid2.device;

import android.content.Context;
import com.snail.antifake.deviceid.ShellAdbUtils;
import com.ta.utdid2.a.a.g;
import java.util.zip.Adler32;

/* JADX INFO: loaded from: classes3.dex */
public class b {
    private static a a = null;
    static final Object d = new Object();

    static long a(a aVar) {
        if (aVar != null) {
            String str = String.format("%s%s%s%s%s", aVar.f(), aVar.getDeviceId(), Long.valueOf(aVar.a()), aVar.getImsi(), aVar.e());
            if (!g.m17a(str)) {
                Adler32 adler32 = new Adler32();
                adler32.reset();
                adler32.update(str.getBytes());
                return adler32.getValue();
            }
            return 0L;
        }
        return 0L;
    }

    private static a a(Context context) {
        if (context != null) {
            synchronized (d) {
                String value = c.a(context).getValue();
                if (!g.m17a(value)) {
                    if (value.endsWith(ShellAdbUtils.COMMAND_LINE_END)) {
                        value = value.substring(0, value.length() - 1);
                    }
                    a aVar = new a();
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    String strA = com.ta.utdid2.a.a.e.a(context);
                    String strC = com.ta.utdid2.a.a.e.c(context);
                    aVar.d(strA);
                    aVar.b(strA);
                    aVar.b(jCurrentTimeMillis);
                    aVar.c(strC);
                    aVar.e(value);
                    aVar.a(a(aVar));
                    return aVar;
                }
                return null;
            }
        }
        return null;
    }

    public static synchronized a b(Context context) {
        if (a != null) {
            return a;
        }
        if (context != null) {
            a aVarA = a(context);
            a = aVarA;
            return aVarA;
        }
        return null;
    }
}
