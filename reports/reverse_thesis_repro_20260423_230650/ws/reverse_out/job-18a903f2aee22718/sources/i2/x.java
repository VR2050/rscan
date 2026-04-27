package i2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class x extends w {

    public static final class a implements y2.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Iterable f9351a;

        public a(Iterable iterable) {
            this.f9351a = iterable;
        }

        @Override // y2.c
        public Iterator iterator() {
            return this.f9351a.iterator();
        }
    }

    public static boolean A(Iterable iterable, Object obj) {
        t2.j.f(iterable, "<this>");
        return iterable instanceof Collection ? ((Collection) iterable).contains(obj) : F(iterable, obj) >= 0;
    }

    public static List B(List list, int i3) {
        t2.j.f(list, "<this>");
        if (i3 >= 0) {
            return AbstractC0586n.Q(list, w2.d.c(list.size() - i3, 0));
        }
        throw new IllegalArgumentException(("Requested element count " + i3 + " is less than zero.").toString());
    }

    public static Collection C(Iterable iterable, Collection collection) {
        t2.j.f(iterable, "<this>");
        t2.j.f(collection, "destination");
        for (Object obj : iterable) {
            if (obj != null) {
                collection.add(obj);
            }
        }
        return collection;
    }

    public static final Object D(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        if (iterable instanceof List) {
            return AbstractC0586n.E((List) iterable);
        }
        Iterator it = iterable.iterator();
        if (it.hasNext()) {
            return it.next();
        }
        throw new NoSuchElementException("Collection is empty.");
    }

    public static Object E(List list) {
        t2.j.f(list, "<this>");
        if (list.isEmpty()) {
            throw new NoSuchElementException("List is empty.");
        }
        return list.get(0);
    }

    public static final int F(Iterable iterable, Object obj) {
        t2.j.f(iterable, "<this>");
        if (iterable instanceof List) {
            return ((List) iterable).indexOf(obj);
        }
        int i3 = 0;
        for (Object obj2 : iterable) {
            if (i3 < 0) {
                AbstractC0586n.n();
            }
            if (t2.j.b(obj, obj2)) {
                return i3;
            }
            i3++;
        }
        return -1;
    }

    public static final Appendable G(Iterable iterable, Appendable appendable, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, s2.l lVar) throws IOException {
        t2.j.f(iterable, "<this>");
        t2.j.f(appendable, "buffer");
        t2.j.f(charSequence, "separator");
        t2.j.f(charSequence2, "prefix");
        t2.j.f(charSequence3, "postfix");
        t2.j.f(charSequence4, "truncated");
        appendable.append(charSequence2);
        int i4 = 0;
        for (Object obj : iterable) {
            i4++;
            if (i4 > 1) {
                appendable.append(charSequence);
            }
            if (i3 >= 0 && i4 > i3) {
                break;
            }
            z2.g.a(appendable, obj, lVar);
        }
        if (i3 >= 0 && i4 > i3) {
            appendable.append(charSequence4);
        }
        appendable.append(charSequence3);
        return appendable;
    }

    public static final String I(Iterable iterable, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, s2.l lVar) {
        t2.j.f(iterable, "<this>");
        t2.j.f(charSequence, "separator");
        t2.j.f(charSequence2, "prefix");
        t2.j.f(charSequence3, "postfix");
        t2.j.f(charSequence4, "truncated");
        String string = ((StringBuilder) G(iterable, new StringBuilder(), charSequence, charSequence2, charSequence3, i3, charSequence4, lVar)).toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    public static /* synthetic */ String J(Iterable iterable, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, s2.l lVar, int i4, Object obj) {
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
        return I(iterable, charSequence, charSequence5, charSequence6, i5, charSequence7, lVar);
    }

    public static Object K(List list) {
        t2.j.f(list, "<this>");
        if (list.isEmpty()) {
            throw new NoSuchElementException("List is empty.");
        }
        return list.get(AbstractC0586n.h(list));
    }

    public static Object L(List list) {
        t2.j.f(list, "<this>");
        if (list.isEmpty()) {
            return null;
        }
        return list.get(list.size() - 1);
    }

    public static List M(Collection collection, Iterable iterable) {
        t2.j.f(collection, "<this>");
        t2.j.f(iterable, "elements");
        if (!(iterable instanceof Collection)) {
            ArrayList arrayList = new ArrayList(collection);
            AbstractC0586n.q(arrayList, iterable);
            return arrayList;
        }
        Collection collection2 = (Collection) iterable;
        ArrayList arrayList2 = new ArrayList(collection.size() + collection2.size());
        arrayList2.addAll(collection);
        arrayList2.addAll(collection2);
        return arrayList2;
    }

    public static List N(Collection collection, Object obj) {
        t2.j.f(collection, "<this>");
        ArrayList arrayList = new ArrayList(collection.size() + 1);
        arrayList.addAll(collection);
        arrayList.add(obj);
        return arrayList;
    }

    public static Object O(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        if (iterable instanceof List) {
            return P((List) iterable);
        }
        Iterator it = iterable.iterator();
        if (!it.hasNext()) {
            throw new NoSuchElementException("Collection is empty.");
        }
        Object next = it.next();
        if (it.hasNext()) {
            throw new IllegalArgumentException("Collection has more than one element.");
        }
        return next;
    }

    public static final Object P(List list) {
        t2.j.f(list, "<this>");
        int size = list.size();
        if (size == 0) {
            throw new NoSuchElementException("List is empty.");
        }
        if (size == 1) {
            return list.get(0);
        }
        throw new IllegalArgumentException("List has more than one element.");
    }

    public static List Q(Iterable iterable, int i3) {
        t2.j.f(iterable, "<this>");
        if (i3 < 0) {
            throw new IllegalArgumentException(("Requested element count " + i3 + " is less than zero.").toString());
        }
        if (i3 == 0) {
            return AbstractC0586n.g();
        }
        if (iterable instanceof Collection) {
            if (i3 >= ((Collection) iterable).size()) {
                return AbstractC0586n.T(iterable);
            }
            if (i3 == 1) {
                return AbstractC0586n.b(D(iterable));
            }
        }
        ArrayList arrayList = new ArrayList(i3);
        Iterator it = iterable.iterator();
        int i4 = 0;
        while (it.hasNext()) {
            arrayList.add(it.next());
            i4++;
            if (i4 == i3) {
                break;
            }
        }
        return p.l(arrayList);
    }

    public static final Collection R(Iterable iterable, Collection collection) {
        t2.j.f(iterable, "<this>");
        t2.j.f(collection, "destination");
        Iterator it = iterable.iterator();
        while (it.hasNext()) {
            collection.add(it.next());
        }
        return collection;
    }

    public static float[] S(Collection collection) {
        t2.j.f(collection, "<this>");
        float[] fArr = new float[collection.size()];
        Iterator it = collection.iterator();
        int i3 = 0;
        while (it.hasNext()) {
            fArr[i3] = ((Number) it.next()).floatValue();
            i3++;
        }
        return fArr;
    }

    public static List T(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        if (!(iterable instanceof Collection)) {
            return p.l(U(iterable));
        }
        Collection collection = (Collection) iterable;
        int size = collection.size();
        if (size == 0) {
            return AbstractC0586n.g();
        }
        if (size != 1) {
            return AbstractC0586n.V(collection);
        }
        return AbstractC0586n.b(iterable instanceof List ? ((List) iterable).get(0) : iterable.iterator().next());
    }

    public static final List U(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        return iterable instanceof Collection ? AbstractC0586n.V((Collection) iterable) : (List) R(iterable, new ArrayList());
    }

    public static List V(Collection collection) {
        t2.j.f(collection, "<this>");
        return new ArrayList(collection);
    }

    public static Set W(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        if (!(iterable instanceof Collection)) {
            return M.c((Set) R(iterable, new LinkedHashSet()));
        }
        Collection collection = (Collection) iterable;
        int size = collection.size();
        if (size == 0) {
            return K.b();
        }
        if (size != 1) {
            return (Set) R(iterable, new LinkedHashSet(D.c(collection.size())));
        }
        return L.a(iterable instanceof List ? ((List) iterable).get(0) : iterable.iterator().next());
    }

    public static List X(Iterable iterable, Iterable iterable2) {
        t2.j.f(iterable, "<this>");
        t2.j.f(iterable2, "other");
        Iterator it = iterable.iterator();
        Iterator it2 = iterable2.iterator();
        ArrayList arrayList = new ArrayList(Math.min(AbstractC0586n.o(iterable, 10), AbstractC0586n.o(iterable2, 10)));
        while (it.hasNext() && it2.hasNext()) {
            arrayList.add(h2.n.a(it.next(), it2.next()));
        }
        return arrayList;
    }

    public static y2.c z(Iterable iterable) {
        t2.j.f(iterable, "<this>");
        return new a(iterable);
    }
}
