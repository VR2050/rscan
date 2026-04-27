package i2;

import h2.C0563i;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class G extends F {
    public static Map f() {
        C0571A c0571a = C0571A.f9331b;
        t2.j.d(c0571a, "null cannot be cast to non-null type kotlin.collections.Map<K of kotlin.collections.MapsKt__MapsKt.emptyMap, V of kotlin.collections.MapsKt__MapsKt.emptyMap>");
        return c0571a;
    }

    public static HashMap g(C0563i... c0563iArr) {
        t2.j.f(c0563iArr, "pairs");
        HashMap map = new HashMap(D.c(c0563iArr.length));
        l(map, c0563iArr);
        return map;
    }

    public static Map h(C0563i... c0563iArr) {
        t2.j.f(c0563iArr, "pairs");
        return c0563iArr.length > 0 ? p(c0563iArr, new LinkedHashMap(D.c(c0563iArr.length))) : D.f();
    }

    public static Map i(C0563i... c0563iArr) {
        t2.j.f(c0563iArr, "pairs");
        LinkedHashMap linkedHashMap = new LinkedHashMap(D.c(c0563iArr.length));
        l(linkedHashMap, c0563iArr);
        return linkedHashMap;
    }

    public static final Map j(Map map) {
        t2.j.f(map, "<this>");
        int size = map.size();
        return size != 0 ? size != 1 ? map : F.e(map) : D.f();
    }

    public static final void k(Map map, Iterable iterable) {
        t2.j.f(map, "<this>");
        t2.j.f(iterable, "pairs");
        Iterator it = iterable.iterator();
        while (it.hasNext()) {
            C0563i c0563i = (C0563i) it.next();
            map.put(c0563i.a(), c0563i.b());
        }
    }

    public static final void l(Map map, C0563i[] c0563iArr) {
        t2.j.f(map, "<this>");
        t2.j.f(c0563iArr, "pairs");
        for (C0563i c0563i : c0563iArr) {
            map.put(c0563i.a(), c0563i.b());
        }
    }

    public static Map m(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        if (!(iterable instanceof Collection)) {
            return j(n(iterable, new LinkedHashMap()));
        }
        Collection collection = (Collection) iterable;
        int size = collection.size();
        if (size == 0) {
            return D.f();
        }
        if (size != 1) {
            return n(iterable, new LinkedHashMap(D.c(collection.size())));
        }
        return D.d((C0563i) (iterable instanceof List ? ((List) iterable).get(0) : iterable.iterator().next()));
    }

    public static final Map n(Iterable iterable, Map map) {
        t2.j.f(iterable, "<this>");
        t2.j.f(map, "destination");
        k(map, iterable);
        return map;
    }

    public static Map o(Map map) {
        t2.j.f(map, "<this>");
        int size = map.size();
        return size != 0 ? size != 1 ? D.q(map) : F.e(map) : D.f();
    }

    public static final Map p(C0563i[] c0563iArr, Map map) {
        t2.j.f(c0563iArr, "<this>");
        t2.j.f(map, "destination");
        l(map, c0563iArr);
        return map;
    }

    public static Map q(Map map) {
        t2.j.f(map, "<this>");
        return new LinkedHashMap(map);
    }
}
