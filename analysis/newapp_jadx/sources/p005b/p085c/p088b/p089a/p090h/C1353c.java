package p005b.p085c.p088b.p089a.p090h;

import android.content.Context;
import android.text.TextUtils;
import java.util.Objects;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p095f.p096d.C1368c;
import p005b.p085c.p088b.p095f.p096d.C1369d;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.a.h.c */
/* loaded from: classes.dex */
public class C1353c {

    /* renamed from: b.c.b.a.h.c$a */
    public static final class a {
        /* renamed from: a */
        public static synchronized void m368a(Context context, C1354d c1354d, String str, String str2) {
            synchronized (a.class) {
                if (c1354d == null || str == null) {
                    return;
                }
                String m373b = c1354d.m373b(str);
                synchronized (a.class) {
                    if (!TextUtils.isEmpty(m373b)) {
                        C4195m.m4802e(context, m373b, str2);
                    }
                    new Thread(new RunnableC1352b(m373b, context)).start();
                }
            }
        }

        /* renamed from: b */
        public static boolean m369b(Context context, String str) {
            boolean z;
            synchronized (a.class) {
                C4195m.m4787T("mspl", "stat sub " + str);
                z = false;
                try {
                    if ((C1356a.m376d().f1203h ? new C1368c() : new C1369d()).mo399a(null, context, str) != null) {
                        C4195m.m4794a(context, str);
                        z = true;
                    }
                } catch (Throwable th) {
                    C4195m.m4816l(th);
                }
            }
            return z;
        }
    }

    /* renamed from: b.c.b.a.h.c$b */
    public static final class b {
    }

    /* renamed from: a */
    public static synchronized void m360a(Context context, C1373a c1373a, String str, String str2) {
        synchronized (C1353c.class) {
            if (context == null || c1373a == null) {
                return;
            }
            try {
                C4195m.m4802e(context, c1373a.f1255i.m373b(str), str2);
            } catch (Throwable th) {
                C4195m.m4816l(th);
            }
        }
    }

    /* renamed from: b */
    public static void m361b(C1373a c1373a, String str, String str2) {
        if (c1373a == null) {
            return;
        }
        c1373a.f1255i.m375f("", str, str2);
    }

    /* renamed from: c */
    public static void m362c(C1373a c1373a, String str, String str2, String str3) {
        if (c1373a == null) {
            return;
        }
        c1373a.f1255i.m374e(str, str2, str3);
    }

    /* renamed from: d */
    public static void m363d(C1373a c1373a, String str, String str2, Throwable th) {
        if (c1373a == null) {
            return;
        }
        C1354d c1354d = c1373a.f1255i;
        Objects.requireNonNull(c1354d);
        c1354d.m374e(str, str2, C1354d.m371c(th));
    }

    /* renamed from: e */
    public static void m364e(C1373a c1373a, String str, String str2, Throwable th, String str3) {
        if (c1373a == null) {
            return;
        }
        C1354d c1354d = c1373a.f1255i;
        Objects.requireNonNull(c1354d);
        c1354d.m374e(str, str2, C1499a.m639y(str3, ": ", C1354d.m371c(th)));
    }

    /* renamed from: f */
    public static void m365f(C1373a c1373a, String str, Throwable th) {
        if (c1373a == null || th.getClass() == null) {
            return;
        }
        C1354d c1354d = c1373a.f1255i;
        String simpleName = th.getClass().getSimpleName();
        Objects.requireNonNull(c1354d);
        c1354d.m374e(str, simpleName, C1354d.m371c(th));
    }

    /* renamed from: g */
    public static synchronized void m366g(Context context, C1373a c1373a, String str, String str2) {
        synchronized (C1353c.class) {
            if (context != null) {
                a.m368a(context, c1373a.f1255i, str, str2);
            }
        }
    }

    /* renamed from: h */
    public static void m367h(C1373a c1373a, String str, String str2, String str3) {
        if (c1373a == null) {
            return;
        }
        C1354d c1354d = c1373a.f1255i;
        Objects.requireNonNull(c1354d);
        c1354d.m375f("", str, str2 + "|" + str3);
    }
}
