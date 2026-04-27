package y2;

import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public final class a implements c, b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final c f10498a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10499b;

    /* JADX INFO: renamed from: y2.a$a, reason: collision with other inner class name */
    public static final class C0161a implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Iterator f10500a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f10501b;

        C0161a(a aVar) {
            this.f10500a = aVar.f10498a.iterator();
            this.f10501b = aVar.f10499b;
        }

        private final void a() {
            while (this.f10501b > 0 && this.f10500a.hasNext()) {
                this.f10500a.next();
                this.f10501b--;
            }
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            a();
            return this.f10500a.hasNext();
        }

        @Override // java.util.Iterator
        public Object next() {
            a();
            return this.f10500a.next();
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public a(c cVar, int i3) {
        t2.j.f(cVar, "sequence");
        this.f10498a = cVar;
        this.f10499b = i3;
        if (i3 >= 0) {
            return;
        }
        throw new IllegalArgumentException(("count must be non-negative, but was " + i3 + '.').toString());
    }

    @Override // y2.b
    public c a(int i3) {
        int i4 = this.f10499b + i3;
        return i4 < 0 ? new a(this, i3) : new a(this.f10498a, i4);
    }

    @Override // y2.c
    public Iterator iterator() {
        return new C0161a(this);
    }
}
