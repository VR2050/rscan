package p005b.p113c0.p114a.p124i;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.util.regex.Pattern;
import p005b.p113c0.p114a.p130l.C1491c;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.c0.a.i.e */
/* loaded from: classes2.dex */
public class C1459e {

    /* renamed from: a */
    public static final Pattern f1419a = Pattern.compile("\\*|\\s*((W\\/)?(\"[^\"]*\"))\\s*,?");

    /* renamed from: b */
    public InterfaceC1457c f1420b;

    /* renamed from: c */
    public InterfaceC1458d f1421c;

    /* renamed from: d */
    public boolean f1422d;

    public C1459e(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
        this.f1420b = interfaceC1457c;
        this.f1421c = interfaceC1458d;
    }

    /* renamed from: a */
    public final String m530a(String str) {
        return TextUtils.isEmpty(str) ? str : ((str.startsWith("\"") || str.startsWith("W/\"")) && str.endsWith("\"")) ? str : C1499a.m639y("\"", str, "\"");
    }

    /* renamed from: b */
    public final long m531b(String str) {
        int indexOf;
        String substring;
        try {
            return this.f1420b.mo529k(str);
        } catch (IllegalStateException unused) {
            String mo528j = this.f1420b.mo528j(str);
            if (TextUtils.isEmpty(mo528j) || (indexOf = mo528j.indexOf(59)) == -1 || (substring = mo528j.substring(0, indexOf)) == null || substring.length() < 3) {
                return -1L;
            }
            return C1491c.m561a(substring);
        }
    }
}
