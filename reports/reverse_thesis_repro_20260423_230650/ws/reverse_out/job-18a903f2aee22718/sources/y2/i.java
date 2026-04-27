package y2;

import i2.AbstractC0586n;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import s2.l;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class i extends h {

    public static final class a implements Iterable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ c f10502b;

        public a(c cVar) {
            this.f10502b = cVar;
        }

        @Override // java.lang.Iterable
        public Iterator iterator() {
            return this.f10502b.iterator();
        }
    }

    public static Iterable a(c cVar) {
        t2.j.f(cVar, "<this>");
        return new a(cVar);
    }

    public static c b(c cVar, int i3) {
        t2.j.f(cVar, "<this>");
        if (i3 >= 0) {
            return i3 == 0 ? cVar : cVar instanceof b ? ((b) cVar).a(i3) : new y2.a(cVar, i3);
        }
        throw new IllegalArgumentException(("Requested element count " + i3 + " is less than zero.").toString());
    }

    public static final Appendable c(c cVar, Appendable appendable, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, l lVar) throws IOException {
        t2.j.f(cVar, "<this>");
        t2.j.f(appendable, "buffer");
        t2.j.f(charSequence, "separator");
        t2.j.f(charSequence2, "prefix");
        t2.j.f(charSequence3, "postfix");
        t2.j.f(charSequence4, "truncated");
        appendable.append(charSequence2);
        int i4 = 0;
        for (Object obj : cVar) {
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

    public static final String d(c cVar, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, l lVar) {
        t2.j.f(cVar, "<this>");
        t2.j.f(charSequence, "separator");
        t2.j.f(charSequence2, "prefix");
        t2.j.f(charSequence3, "postfix");
        t2.j.f(charSequence4, "truncated");
        String string = ((StringBuilder) c(cVar, new StringBuilder(), charSequence, charSequence2, charSequence3, i3, charSequence4, lVar)).toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    public static /* synthetic */ String e(c cVar, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, int i3, CharSequence charSequence4, l lVar, int i4, Object obj) {
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
        return d(cVar, charSequence, charSequence5, charSequence6, i5, charSequence7, lVar);
    }

    public static c f(c cVar, l lVar) {
        t2.j.f(cVar, "<this>");
        t2.j.f(lVar, "transform");
        return new j(cVar, lVar);
    }

    public static List g(c cVar) {
        t2.j.f(cVar, "<this>");
        Iterator it = cVar.iterator();
        if (!it.hasNext()) {
            return AbstractC0586n.g();
        }
        Object next = it.next();
        if (!it.hasNext()) {
            return AbstractC0586n.b(next);
        }
        ArrayList arrayList = new ArrayList();
        arrayList.add(next);
        while (it.hasNext()) {
            arrayList.add(it.next());
        }
        return arrayList;
    }
}
