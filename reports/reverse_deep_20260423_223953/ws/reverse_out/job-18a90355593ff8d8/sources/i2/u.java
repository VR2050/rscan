package i2;

import java.util.Collection;
import java.util.Iterator;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class u extends t {
    public static boolean q(Collection collection, Iterable iterable) {
        t2.j.f(collection, "<this>");
        t2.j.f(iterable, "elements");
        if (iterable instanceof Collection) {
            return collection.addAll((Collection) iterable);
        }
        Iterator it = iterable.iterator();
        boolean z3 = false;
        while (it.hasNext()) {
            if (collection.add(it.next())) {
                z3 = true;
            }
        }
        return z3;
    }

    public static boolean r(Collection collection, Object[] objArr) {
        t2.j.f(collection, "<this>");
        t2.j.f(objArr, "elements");
        return collection.addAll(AbstractC0580h.d(objArr));
    }
}
