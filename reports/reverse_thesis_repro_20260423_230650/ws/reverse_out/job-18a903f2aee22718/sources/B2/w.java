package B2;

import B2.m;
import i2.AbstractC0586n;
import java.io.IOException;
import java.net.CookieHandler;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class w implements n {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final CookieHandler f434c;

    public w(CookieHandler cookieHandler) {
        t2.j.f(cookieHandler, "cookieHandler");
        this.f434c = cookieHandler;
    }

    private final List e(u uVar, String str) {
        ArrayList arrayList = new ArrayList();
        int length = str.length();
        int i3 = 0;
        while (i3 < length) {
            int iN = C2.c.n(str, ";,", i3, length);
            int iM = C2.c.m(str, '=', i3, iN);
            String strV = C2.c.V(str, i3, iM);
            if (!z2.g.u(strV, "$", false, 2, null)) {
                String strV2 = iM < iN ? C2.c.V(str, iM + 1, iN) : "";
                if (z2.g.u(strV2, "\"", false, 2, null) && z2.g.i(strV2, "\"", false, 2, null)) {
                    strV2 = strV2.substring(1, strV2.length() - 1);
                    t2.j.e(strV2, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                }
                arrayList.add(new m.a().d(strV).e(strV2).b(uVar.h()).a());
            }
            i3 = iN + 1;
        }
        return arrayList;
    }

    @Override // B2.n
    public void b(u uVar, List list) {
        t2.j.f(uVar, "url");
        t2.j.f(list, "cookies");
        ArrayList arrayList = new ArrayList();
        Iterator it = list.iterator();
        while (it.hasNext()) {
            arrayList.add(C2.b.a((m) it.next(), true));
        }
        try {
            this.f434c.put(uVar.q(), i2.D.d(h2.n.a("Set-Cookie", arrayList)));
        } catch (IOException e3) {
            L2.j jVarG = L2.j.f1746c.g();
            StringBuilder sb = new StringBuilder();
            sb.append("Saving cookies failed for ");
            u uVarO = uVar.o("/...");
            t2.j.c(uVarO);
            sb.append(uVarO);
            jVarG.k(sb.toString(), 5, e3);
        }
    }

    @Override // B2.n
    public List c(u uVar) {
        t2.j.f(uVar, "url");
        try {
            Map<String, List<String>> map = this.f434c.get(uVar.q(), i2.D.f());
            t2.j.e(map, "cookieHeaders");
            ArrayList arrayList = null;
            for (Map.Entry<String, List<String>> entry : map.entrySet()) {
                String key = entry.getKey();
                List<String> value = entry.getValue();
                if (z2.g.j("Cookie", key, true) || z2.g.j("Cookie2", key, true)) {
                    t2.j.e(value, "value");
                    if (!value.isEmpty()) {
                        for (String str : value) {
                            if (arrayList == null) {
                                arrayList = new ArrayList();
                            }
                            t2.j.e(str, "header");
                            arrayList.addAll(e(uVar, str));
                        }
                    }
                }
            }
            if (arrayList == null) {
                return AbstractC0586n.g();
            }
            List listUnmodifiableList = Collections.unmodifiableList(arrayList);
            t2.j.e(listUnmodifiableList, "Collections.unmodifiableList(cookies)");
            return listUnmodifiableList;
        } catch (IOException e3) {
            L2.j jVarG = L2.j.f1746c.g();
            StringBuilder sb = new StringBuilder();
            sb.append("Loading cookies failed for ");
            u uVarO = uVar.o("/...");
            t2.j.c(uVarO);
            sb.append(uVarO);
            jVarG.k(sb.toString(), 5, e3);
            return AbstractC0586n.g();
        }
    }
}
