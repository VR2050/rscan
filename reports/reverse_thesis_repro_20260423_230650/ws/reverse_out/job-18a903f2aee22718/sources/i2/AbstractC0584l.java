package i2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: renamed from: i2.l, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0584l extends AbstractC0583k {
    public static Object A(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        if (objArr.length == 1) {
            return objArr[0];
        }
        return null;
    }

    public static List B(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        int length = objArr.length;
        return length != 0 ? length != 1 ? AbstractC0580h.C(objArr) : AbstractC0586n.b(objArr[0]) : AbstractC0586n.g();
    }

    public static List C(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        return new ArrayList(p.d(objArr));
    }

    public static final boolean l(Object[] objArr, Object obj) {
        t2.j.f(objArr, "<this>");
        return t(objArr, obj) >= 0;
    }

    public static List m(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        return (List) n(objArr, new ArrayList());
    }

    public static final Collection n(Object[] objArr, Collection collection) {
        t2.j.f(objArr, "<this>");
        t2.j.f(collection, "destination");
        for (Object obj : objArr) {
            if (obj != null) {
                collection.add(obj);
            }
        }
        return collection;
    }

    public static w2.c o(byte[] bArr) {
        t2.j.f(bArr, "<this>");
        return new w2.c(0, q(bArr));
    }

    public static w2.c p(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        return new w2.c(0, AbstractC0580h.r(objArr));
    }

    public static final int q(byte[] bArr) {
        t2.j.f(bArr, "<this>");
        return bArr.length - 1;
    }

    public static int r(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        return objArr.length - 1;
    }

    public static Object s(Object[] objArr, int i3) {
        t2.j.f(objArr, "<this>");
        if (i3 < 0 || i3 >= objArr.length) {
            return null;
        }
        return objArr[i3];
    }

    public static final int t(Object[] objArr, Object obj) {
        t2.j.f(objArr, "<this>");
        int i3 = 0;
        if (obj == null) {
            int length = objArr.length;
            while (i3 < length) {
                if (objArr[i3] == null) {
                    return i3;
                }
                i3++;
            }
            return -1;
        }
        int length2 = objArr.length;
        while (i3 < length2) {
            if (t2.j.b(obj, objArr[i3])) {
                return i3;
            }
            i3++;
        }
        return -1;
    }

    public static final Appendable u(int[] iArr, Appendable appendable, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, s2.l lVar) throws IOException {
        t2.j.f(iArr, "<this>");
        t2.j.f(appendable, "buffer");
        t2.j.f(charSequence, "separator");
        t2.j.f(charSequence2, "prefix");
        t2.j.f(charSequence3, "postfix");
        t2.j.f(charSequence4, "truncated");
        appendable.append(charSequence2);
        int i4 = 0;
        for (int i5 : iArr) {
            i4++;
            if (i4 > 1) {
                appendable.append(charSequence);
            }
            if (i3 >= 0 && i4 > i3) {
                break;
            }
            if (lVar != null) {
                appendable.append((CharSequence) lVar.d(Integer.valueOf(i5)));
            } else {
                appendable.append(String.valueOf(i5));
            }
        }
        if (i3 >= 0 && i4 > i3) {
            appendable.append(charSequence4);
        }
        appendable.append(charSequence3);
        return appendable;
    }

    public static final String v(int[] iArr, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, s2.l lVar) {
        t2.j.f(iArr, "<this>");
        t2.j.f(charSequence, "separator");
        t2.j.f(charSequence2, "prefix");
        t2.j.f(charSequence3, "postfix");
        t2.j.f(charSequence4, "truncated");
        String string = ((StringBuilder) u(iArr, new StringBuilder(), charSequence, charSequence2, charSequence3, i3, charSequence4, lVar)).toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    public static /* synthetic */ String w(int[] iArr, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, s2.l lVar, int i4, Object obj) {
        if ((i4 & 1) != 0) {
            charSequence = ", ";
        }
        CharSequence charSequence5 = (i4 & 2) != 0 ? "" : charSequence2;
        CharSequence charSequence6 = (i4 & 4) == 0 ? charSequence3 : "";
        if ((i4 & 8) != 0) {
            i3 = -1;
        }
        int i5 = i3;
        if ((i4 & 16) != 0) {
            charSequence4 = "...";
        }
        CharSequence charSequence7 = charSequence4;
        if ((i4 & 32) != 0) {
            lVar = null;
        }
        return v(iArr, charSequence, charSequence5, charSequence6, i5, charSequence7, lVar);
    }

    public static Object x(Object[] objArr) {
        t2.j.f(objArr, "<this>");
        if (objArr.length != 0) {
            return objArr[AbstractC0580h.r(objArr)];
        }
        throw new NoSuchElementException("Array is empty.");
    }

    public static Comparable y(Comparable[] comparableArr) {
        t2.j.f(comparableArr, "<this>");
        if (comparableArr.length == 0) {
            return null;
        }
        Comparable comparable = comparableArr[0];
        int iR = AbstractC0580h.r(comparableArr);
        int i3 = 1;
        if (1 <= iR) {
            while (true) {
                Comparable comparable2 = comparableArr[i3];
                if (comparable.compareTo(comparable2) < 0) {
                    comparable = comparable2;
                }
                if (i3 == iR) {
                    break;
                }
                i3++;
            }
        }
        return comparable;
    }

    public static char z(char[] cArr) {
        t2.j.f(cArr, "<this>");
        int length = cArr.length;
        if (length == 0) {
            throw new NoSuchElementException("Array is empty.");
        }
        if (length == 1) {
            return cArr[0];
        }
        throw new IllegalArgumentException("Array has more than one element.");
    }
}
