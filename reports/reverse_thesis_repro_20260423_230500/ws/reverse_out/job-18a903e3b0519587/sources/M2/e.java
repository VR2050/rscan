package M2;

import B2.z;
import android.util.Log;
import i2.D;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Level;
import java.util.logging.Logger;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Map f1813b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final e f1814c = new e();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final CopyOnWriteArraySet f1812a = new CopyOnWriteArraySet();

    static {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Package r22 = z.class.getPackage();
        String name = r22 != null ? r22.getName() : null;
        if (name != null) {
            linkedHashMap.put(name, "OkHttp");
        }
        String name2 = z.class.getName();
        t2.j.e(name2, "OkHttpClient::class.java.name");
        linkedHashMap.put(name2, "okhttp.OkHttpClient");
        String name3 = J2.e.class.getName();
        t2.j.e(name3, "Http2::class.java.name");
        linkedHashMap.put(name3, "okhttp.Http2");
        String name4 = F2.e.class.getName();
        t2.j.e(name4, "TaskRunner::class.java.name");
        linkedHashMap.put(name4, "okhttp.TaskRunner");
        linkedHashMap.put("okhttp3.mockwebserver.MockWebServer", "okhttp.MockWebServer");
        f1813b = D.o(linkedHashMap);
    }

    private e() {
    }

    private final void c(String str, String str2) {
        Logger logger = Logger.getLogger(str);
        if (f1812a.add(logger)) {
            t2.j.e(logger, "logger");
            logger.setUseParentHandlers(false);
            logger.setLevel(Log.isLoggable(str2, 3) ? Level.FINE : Log.isLoggable(str2, 4) ? Level.INFO : Level.WARNING);
            logger.addHandler(f.f1815a);
        }
    }

    private final String d(String str) {
        String str2 = (String) f1813b.get(str);
        return str2 != null ? str2 : z2.g.o0(str, 23);
    }

    public final void a(String str, int i3, String str2, Throwable th) {
        int iMin;
        t2.j.f(str, "loggerName");
        t2.j.f(str2, "message");
        String strD = d(str);
        if (Log.isLoggable(strD, i3)) {
            if (th != null) {
                str2 = str2 + "\n" + Log.getStackTraceString(th);
            }
            int length = str2.length();
            int i4 = 0;
            while (i4 < length) {
                int I3 = z2.g.I(str2, '\n', i4, false, 4, null);
                if (I3 == -1) {
                    I3 = length;
                }
                while (true) {
                    iMin = Math.min(I3, i4 + 4000);
                    String strSubstring = str2.substring(i4, iMin);
                    t2.j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                    Log.println(i3, strD, strSubstring);
                    if (iMin >= I3) {
                        break;
                    } else {
                        i4 = iMin;
                    }
                }
                i4 = iMin + 1;
            }
        }
    }

    public final void b() {
        for (Map.Entry entry : f1813b.entrySet()) {
            c((String) entry.getKey(), (String) entry.getValue());
        }
    }
}
