package i2;

import java.util.Collection;
import java.util.Iterator;

/* JADX INFO: renamed from: i2.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
final class C0578f implements Collection {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Object[] f9344b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f9345c;

    public C0578f(Object[] objArr, boolean z3) {
        t2.j.f(objArr, "values");
        this.f9344b = objArr;
        this.f9345c = z3;
    }

    public int a() {
        return this.f9344b.length;
    }

    @Override // java.util.Collection
    public boolean add(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Collection
    public boolean addAll(Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Collection
    public void clear() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Collection
    public boolean contains(Object obj) {
        return AbstractC0584l.l(this.f9344b, obj);
    }

    @Override // java.util.Collection
    public boolean containsAll(Collection collection) {
        t2.j.f(collection, "elements");
        if (collection.isEmpty()) {
            return true;
        }
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            if (!contains(it.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.Collection
    public boolean isEmpty() {
        return this.f9344b.length == 0;
    }

    @Override // java.util.Collection, java.lang.Iterable
    public Iterator iterator() {
        return t2.b.a(this.f9344b);
    }

    @Override // java.util.Collection
    public boolean remove(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Collection
    public boolean removeAll(Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Collection
    public boolean retainAll(Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Collection
    public final /* bridge */ int size() {
        return a();
    }

    @Override // java.util.Collection
    public Object[] toArray(Object[] objArr) {
        t2.j.f(objArr, "array");
        return t2.f.b(this, objArr);
    }

    @Override // java.util.Collection
    public final Object[] toArray() {
        return o.a(this.f9344b, this.f9345c);
    }
}
