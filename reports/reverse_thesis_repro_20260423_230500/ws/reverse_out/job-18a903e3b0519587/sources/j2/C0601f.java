package j2;

import i2.AbstractC0575c;
import java.util.Collection;
import java.util.Iterator;
import t2.j;

/* JADX INFO: renamed from: j2.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0601f extends AbstractC0575c implements Collection {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0598c f9395b;

    public C0601f(C0598c c0598c) {
        j.f(c0598c, "backing");
        this.f9395b = c0598c;
    }

    @Override // i2.AbstractC0575c
    public int a() {
        return this.f9395b.size();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean add(Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean addAll(Collection collection) {
        j.f(collection, "elements");
        throw new UnsupportedOperationException();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public void clear() {
        this.f9395b.clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean contains(Object obj) {
        return this.f9395b.containsValue(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean isEmpty() {
        return this.f9395b.isEmpty();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public Iterator iterator() {
        return this.f9395b.N();
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean remove(Object obj) {
        return this.f9395b.L(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean removeAll(Collection collection) {
        j.f(collection, "elements");
        this.f9395b.k();
        return super.removeAll(collection);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean retainAll(Collection collection) {
        j.f(collection, "elements");
        this.f9395b.k();
        return super.retainAll(collection);
    }
}
