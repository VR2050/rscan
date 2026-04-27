package i2;

import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

/* JADX INFO: loaded from: classes.dex */
class J extends AbstractC0574b {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f9333c;

    public static final class a implements ListIterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ListIterator f9334a;

        a(int i3) {
            this.f9334a = J.this.f9333c.listIterator(v.y(J.this, i3));
        }

        @Override // java.util.ListIterator
        public void add(Object obj) {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }

        @Override // java.util.ListIterator, java.util.Iterator
        public boolean hasNext() {
            return this.f9334a.hasPrevious();
        }

        @Override // java.util.ListIterator
        public boolean hasPrevious() {
            return this.f9334a.hasNext();
        }

        @Override // java.util.ListIterator, java.util.Iterator
        public Object next() {
            return this.f9334a.previous();
        }

        @Override // java.util.ListIterator
        public int nextIndex() {
            return v.x(J.this, this.f9334a.previousIndex());
        }

        @Override // java.util.ListIterator
        public Object previous() {
            return this.f9334a.next();
        }

        @Override // java.util.ListIterator
        public int previousIndex() {
            return v.x(J.this, this.f9334a.nextIndex());
        }

        @Override // java.util.ListIterator, java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }

        @Override // java.util.ListIterator
        public void set(Object obj) {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public J(List list) {
        t2.j.f(list, "delegate");
        this.f9333c = list;
    }

    @Override // i2.AbstractC0573a
    public int a() {
        return this.f9333c.size();
    }

    @Override // i2.AbstractC0574b, java.util.List
    public Object get(int i3) {
        return this.f9333c.get(v.w(this, i3));
    }

    @Override // i2.AbstractC0574b, java.util.Collection, java.lang.Iterable, java.util.List
    public Iterator iterator() {
        return listIterator(0);
    }

    @Override // i2.AbstractC0574b, java.util.List
    public ListIterator listIterator() {
        return listIterator(0);
    }

    @Override // i2.AbstractC0574b, java.util.List
    public ListIterator listIterator(int i3) {
        return new a(i3);
    }
}
