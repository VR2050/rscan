package i2;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class o {
    public static final Object[] a(Object[] objArr, boolean z3) {
        t2.j.f(objArr, "<this>");
        if (z3 && t2.j.b(objArr.getClass(), Object[].class)) {
            return objArr;
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length, Object[].class);
        t2.j.e(objArrCopyOf, "copyOf(...)");
        return objArrCopyOf;
    }

    public static List b(Object obj) {
        List listSingletonList = Collections.singletonList(obj);
        t2.j.e(listSingletonList, "singletonList(...)");
        return listSingletonList;
    }

    public static final Object[] c(int i3, Object[] objArr) {
        t2.j.f(objArr, "array");
        if (i3 < objArr.length) {
            objArr[i3] = null;
        }
        return objArr;
    }
}
