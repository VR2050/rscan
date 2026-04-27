package Z;

import h2.n;
import i2.D;
import java.util.Locale;
import java.util.Map;
import t2.j;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f2905a = new a();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final Map f2906b = D.h(n.a("mkv", "video/x-matroska"), n.a("glb", "model/gltf-binary"));

    private a() {
    }

    private final String a(String str) {
        int iO = g.O(str, '.', 0, false, 6, null);
        if (iO < 0 || iO == str.length() - 1) {
            return null;
        }
        String strSubstring = str.substring(iO + 1);
        j.e(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static final String b(String str) {
        j.f(str, "path");
        String strA = f2905a.a(str);
        if (strA == null) {
            return null;
        }
        Locale locale = Locale.US;
        j.e(locale, "US");
        String lowerCase = strA.toLowerCase(locale);
        j.e(lowerCase, "toLowerCase(...)");
        if (lowerCase == null) {
            return null;
        }
        String strA2 = b.a(lowerCase);
        return strA2 == null ? (String) f2906b.get(lowerCase) : strA2;
    }

    public static final boolean c(String str) {
        if (str != null) {
            return g.u(str, "video/", false, 2, null);
        }
        return false;
    }
}
