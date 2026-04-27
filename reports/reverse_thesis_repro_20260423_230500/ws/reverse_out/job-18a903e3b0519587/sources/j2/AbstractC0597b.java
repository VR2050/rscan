package j2;

import java.util.Arrays;
import t2.j;

/* JADX INFO: renamed from: j2.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0597b {
    public static final Object[] a(int i3) {
        if (i3 >= 0) {
            return new Object[i3];
        }
        throw new IllegalArgumentException("capacity must be non-negative.");
    }

    public static final Object[] b(Object[] objArr, int i3) {
        j.f(objArr, "<this>");
        Object[] objArrCopyOf = Arrays.copyOf(objArr, i3);
        j.e(objArrCopyOf, "copyOf(...)");
        return objArrCopyOf;
    }

    public static final void c(Object[] objArr, int i3) {
        j.f(objArr, "<this>");
        objArr[i3] = null;
    }

    public static final void d(Object[] objArr, int i3, int i4) {
        j.f(objArr, "<this>");
        while (i3 < i4) {
            c(objArr, i3);
            i3++;
        }
    }
}
