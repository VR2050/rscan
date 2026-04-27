package i2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import k2.AbstractC0605a;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class p extends o {
    public static final Collection d(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        return new C0578f(objArr, false);
    }

    public static final int e(List list, Comparable comparable, int i3, int i4) {
        t2.j.f(list, "<this>");
        m(list.size(), i3, i4);
        int i5 = i4 - 1;
        while (i3 <= i5) {
            int i6 = (i3 + i5) >>> 1;
            int iA = AbstractC0605a.a((Comparable) list.get(i6), comparable);
            if (iA < 0) {
                i3 = i6 + 1;
            } else {
                if (iA <= 0) {
                    return i6;
                }
                i5 = i6 - 1;
            }
        }
        return -(i3 + 1);
    }

    public static /* synthetic */ int f(List list, Comparable comparable, int i3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i3 = 0;
        }
        if ((i5 & 4) != 0) {
            i4 = list.size();
        }
        return e(list, comparable, i3, i4);
    }

    public static List g() {
        return z.f9353b;
    }

    public static int h(List list) {
        t2.j.f(list, "<this>");
        return list.size() - 1;
    }

    public static List i(Object... objArr) {
        t2.j.f(objArr, "elements");
        return objArr.length > 0 ? AbstractC0580h.d(objArr) : AbstractC0586n.g();
    }

    public static List j(Object... objArr) {
        t2.j.f(objArr, "elements");
        return AbstractC0580h.m(objArr);
    }

    public static List k(Object... objArr) {
        t2.j.f(objArr, "elements");
        return objArr.length == 0 ? new ArrayList() : new ArrayList(new C0578f(objArr, true));
    }

    public static final List l(List list) {
        t2.j.f(list, "<this>");
        int size = list.size();
        return size != 0 ? size != 1 ? list : AbstractC0586n.b(list.get(0)) : AbstractC0586n.g();
    }

    private static final void m(int i3, int i4, int i5) {
        if (i4 > i5) {
            throw new IllegalArgumentException("fromIndex (" + i4 + ") is greater than toIndex (" + i5 + ").");
        }
        if (i4 < 0) {
            throw new IndexOutOfBoundsException("fromIndex (" + i4 + ") is less than zero.");
        }
        if (i5 <= i3) {
            return;
        }
        throw new IndexOutOfBoundsException("toIndex (" + i5 + ") is greater than size (" + i3 + ").");
    }

    public static void n() {
        throw new ArithmeticException("Index overflow has happened.");
    }
}
