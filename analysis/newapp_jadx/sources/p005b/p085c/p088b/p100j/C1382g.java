package p005b.p085c.p088b.p100j;

import android.content.Context;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p093d.C1360a;
import p005b.p085c.p088b.p093d.C1361b;
import p005b.p085c.p088b.p098h.C1373a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.j.g */
/* loaded from: classes.dex */
public class C1382g {

    /* renamed from: a */
    public static String f1302a;

    /* renamed from: a */
    public static String m434a(Context context) {
        String str;
        if (TextUtils.isEmpty(f1302a)) {
            try {
                str = context.getApplicationContext().getPackageName();
            } catch (Throwable th) {
                C4195m.m4816l(th);
                str = "";
            }
            f1302a = (str + "0000000000000000000000000000").substring(0, 24);
        }
        return f1302a;
    }

    /* renamed from: b */
    public static synchronized void m435b(C1373a c1373a, Context context, String str, String str2) {
        String str3;
        synchronized (C1382g.class) {
            try {
                try {
                    str3 = C1360a.m387a(C1361b.m391a(m434a(context), str2.getBytes(), str));
                } catch (Exception unused) {
                    str3 = null;
                }
                if (!TextUtils.isEmpty(str2) && TextUtils.isEmpty(str3)) {
                    C1353c.m362c(c1373a, "cp", "TriDesDecryptError", String.format("%s,%s", str, str2));
                }
                PreferenceManager.getDefaultSharedPreferences(context).edit().putString(str, str3).apply();
            } catch (Throwable th) {
                C4195m.m4816l(th);
            }
        }
    }

    /* renamed from: c */
    public static synchronized String m436c(C1373a c1373a, Context context, String str, String str2) {
        String str3;
        synchronized (C1382g.class) {
            str3 = null;
            try {
                String string = PreferenceManager.getDefaultSharedPreferences(context).getString(str, str2);
                if (!TextUtils.isEmpty(string)) {
                    try {
                        str3 = new String(C1361b.m392b(m434a(context), C1360a.m388b(string), str));
                    } catch (Exception unused) {
                    }
                }
                if (!TextUtils.isEmpty(string) && TextUtils.isEmpty(str3)) {
                    C1353c.m362c(c1373a, "cp", "TriDesEncryptError", String.format("%s,%s", str, string));
                }
            } catch (Exception e2) {
                C4195m.m4816l(e2);
            }
        }
        return str3;
    }
}
