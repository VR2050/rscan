package t2;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* JADX INFO: loaded from: classes.dex */
final class a implements Iterator {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object[] f10189a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f10190b;

    public a(Object[] objArr) {
        j.f(objArr, "array");
        this.f10189a = objArr;
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.f10190b < this.f10189a.length;
    }

    @Override // java.util.Iterator
    public Object next() {
        try {
            Object[] objArr = this.f10189a;
            int i3 = this.f10190b;
            this.f10190b = i3 + 1;
            return objArr[i3];
        } catch (ArrayIndexOutOfBoundsException e3) {
            this.f10190b--;
            throw new NoSuchElementException(e3.getMessage());
        }
    }

    @Override // java.util.Iterator
    public void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
