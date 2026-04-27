package y2;

import java.util.Iterator;
import s2.l;

/* JADX INFO: loaded from: classes.dex */
public final class j implements c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final c f10503a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final l f10504b;

    public static final class a implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Iterator f10505a;

        a() {
            this.f10505a = j.this.f10503a.iterator();
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f10505a.hasNext();
        }

        @Override // java.util.Iterator
        public Object next() {
            return j.this.f10504b.d(this.f10505a.next());
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public j(c cVar, l lVar) {
        t2.j.f(cVar, "sequence");
        t2.j.f(lVar, "transformer");
        this.f10503a = cVar;
        this.f10504b = lVar;
    }

    @Override // y2.c
    public Iterator iterator() {
        return new a();
    }
}
