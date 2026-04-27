package androidx.appcompat.app;

import java.util.LinkedHashSet;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
abstract class v {
    private static androidx.core.os.c a(androidx.core.os.c cVar, androidx.core.os.c cVar2) {
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        int i3 = 0;
        while (i3 < cVar.f() + cVar2.f()) {
            Locale localeC = i3 < cVar.f() ? cVar.c(i3) : cVar2.c(i3 - cVar.f());
            if (localeC != null) {
                linkedHashSet.add(localeC);
            }
            i3++;
        }
        return androidx.core.os.c.a((Locale[]) linkedHashSet.toArray(new Locale[linkedHashSet.size()]));
    }

    static androidx.core.os.c b(androidx.core.os.c cVar, androidx.core.os.c cVar2) {
        return (cVar == null || cVar.e()) ? androidx.core.os.c.d() : a(cVar, cVar2);
    }
}
