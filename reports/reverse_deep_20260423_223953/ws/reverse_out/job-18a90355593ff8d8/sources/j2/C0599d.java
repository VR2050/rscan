package j2;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import t2.j;

/* JADX INFO: renamed from: j2.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0599d extends AbstractC0596a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0598c f9393b;

    public C0599d(C0598c c0598c) {
        j.f(c0598c, "backing");
        this.f9393b = c0598c;
    }

    @Override // i2.AbstractC0577e
    public int a() {
        return this.f9393b.size();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean addAll(Collection collection) {
        j.f(collection, "elements");
        throw new UnsupportedOperationException();
    }

    @Override // j2.AbstractC0596a
    public boolean c(Map.Entry entry) {
        j.f(entry, "element");
        return this.f9393b.n(entry);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public void clear() {
        this.f9393b.clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean containsAll(Collection collection) {
        j.f(collection, "elements");
        return this.f9393b.m(collection);
    }

    @Override // j2.AbstractC0596a
    public boolean e(Map.Entry entry) {
        j.f(entry, "element");
        return this.f9393b.H(entry);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public boolean add(Map.Entry entry) {
        j.f(entry, "element");
        throw new UnsupportedOperationException();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean isEmpty() {
        return this.f9393b.isEmpty();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public Iterator iterator() {
        return this.f9393b.r();
    }

    @Override // java.util.AbstractSet, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean removeAll(Collection collection) {
        j.f(collection, "elements");
        this.f9393b.k();
        return super.removeAll(collection);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean retainAll(Collection collection) {
        j.f(collection, "elements");
        this.f9393b.k();
        return super.retainAll(collection);
    }
}
