package p005b.p199l.p258c;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* renamed from: b.l.c.l */
/* loaded from: classes2.dex */
public final class C2482l extends AbstractC2485o implements Iterable<AbstractC2485o> {

    /* renamed from: c */
    public final List<AbstractC2485o> f6694c = new ArrayList();

    public boolean equals(Object obj) {
        return obj == this || ((obj instanceof C2482l) && ((C2482l) obj).f6694c.equals(this.f6694c));
    }

    public int hashCode() {
        return this.f6694c.hashCode();
    }

    @Override // java.lang.Iterable
    public Iterator<AbstractC2485o> iterator() {
        return this.f6694c.iterator();
    }
}
