package R;

import f0.AbstractC0525c;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final e f2615a = new e();

    private e() {
    }

    public static final String a(d dVar) {
        t2.j.f(dVar, "key");
        try {
            if (!(dVar instanceof f)) {
                return f2615a.c(dVar);
            }
            List listD = ((f) dVar).d();
            t2.j.e(listD, "getCacheKeys(...)");
            e eVar = f2615a;
            Object obj = listD.get(0);
            t2.j.e(obj, "get(...)");
            return eVar.c((d) obj);
        } catch (UnsupportedEncodingException e3) {
            throw new RuntimeException(e3);
        }
    }

    public static final List b(d dVar) {
        ArrayList arrayList;
        t2.j.f(dVar, "key");
        try {
            if (dVar instanceof f) {
                List listD = ((f) dVar).d();
                t2.j.e(listD, "getCacheKeys(...)");
                arrayList = new ArrayList(listD.size());
                int size = listD.size();
                for (int i3 = 0; i3 < size; i3++) {
                    e eVar = f2615a;
                    Object obj = listD.get(i3);
                    t2.j.e(obj, "get(...)");
                    arrayList.add(eVar.c((d) obj));
                }
            } else {
                arrayList = new ArrayList(1);
                arrayList.add(dVar.a() ? dVar.c() : f2615a.c(dVar));
            }
            return arrayList;
        } catch (UnsupportedEncodingException e3) {
            throw new RuntimeException(e3);
        }
    }

    private final String c(d dVar) {
        String strC = dVar.c();
        t2.j.e(strC, "getUriString(...)");
        Charset charsetForName = Charset.forName("UTF-8");
        t2.j.e(charsetForName, "forName(...)");
        byte[] bytes = strC.getBytes(charsetForName);
        t2.j.e(bytes, "getBytes(...)");
        String strA = AbstractC0525c.a(bytes);
        t2.j.e(strA, "makeSHA1HashBase64(...)");
        return strA;
    }
}
