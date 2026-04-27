package i2;

import h2.C0563i;
import j2.C0598c;
import java.util.Collections;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class F extends E {
    public static Map a(Map map) {
        t2.j.f(map, "builder");
        return ((C0598c) map).j();
    }

    public static Map b() {
        return new C0598c();
    }

    public static int c(int i3) {
        if (i3 < 0) {
            return i3;
        }
        if (i3 < 3) {
            return i3 + 1;
        }
        if (i3 < 1073741824) {
            return (int) ((i3 / 0.75f) + 1.0f);
        }
        return Integer.MAX_VALUE;
    }

    public static Map d(C0563i c0563i) {
        t2.j.f(c0563i, "pair");
        Map mapSingletonMap = Collections.singletonMap(c0563i.c(), c0563i.d());
        t2.j.e(mapSingletonMap, "singletonMap(...)");
        return mapSingletonMap;
    }

    public static final Map e(Map map) {
        t2.j.f(map, "<this>");
        Map.Entry entry = (Map.Entry) map.entrySet().iterator().next();
        Map mapSingletonMap = Collections.singletonMap(entry.getKey(), entry.getValue());
        t2.j.e(mapSingletonMap, "with(...)");
        return mapSingletonMap;
    }
}
