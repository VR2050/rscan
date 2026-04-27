package i2;

import java.util.AbstractList;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: i2.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0579g extends AbstractC0576d {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f9346e = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Object[] f9347f = new Object[0];

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f9348b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Object[] f9349c = f9347f;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f9350d;

    /* JADX INFO: renamed from: i2.g$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    private final void c(int i3, Collection collection) {
        Iterator it = collection.iterator();
        int length = this.f9349c.length;
        while (i3 < length && it.hasNext()) {
            this.f9349c[i3] = it.next();
            i3++;
        }
        int i4 = this.f9348b;
        for (int i5 = 0; i5 < i4 && it.hasNext(); i5++) {
            this.f9349c[i5] = it.next();
        }
        this.f9350d = size() + collection.size();
    }

    private final void e(int i3) {
        Object[] objArr = new Object[i3];
        Object[] objArr2 = this.f9349c;
        AbstractC0583k.f(objArr2, objArr, 0, this.f9348b, objArr2.length);
        Object[] objArr3 = this.f9349c;
        int length = objArr3.length;
        int i4 = this.f9348b;
        AbstractC0583k.f(objArr3, objArr, length - i4, 0, i4);
        this.f9348b = 0;
        this.f9349c = objArr;
    }

    private final int f(int i3) {
        return i3 == 0 ? AbstractC0580h.r(this.f9349c) : i3 - 1;
    }

    private final void h(int i3) {
        if (i3 < 0) {
            throw new IllegalStateException("Deque is too big.");
        }
        Object[] objArr = this.f9349c;
        if (i3 <= objArr.length) {
            return;
        }
        if (objArr == f9347f) {
            this.f9349c = new Object[w2.d.c(i3, 10)];
        } else {
            e(AbstractC0574b.f9337b.d(objArr.length, i3));
        }
    }

    private final int i(int i3) {
        if (i3 == AbstractC0580h.r(this.f9349c)) {
            return 0;
        }
        return i3 + 1;
    }

    private final int j(int i3) {
        return i3 < 0 ? i3 + this.f9349c.length : i3;
    }

    private final void k(int i3, int i4) {
        if (i3 < i4) {
            AbstractC0580h.j(this.f9349c, null, i3, i4);
            return;
        }
        Object[] objArr = this.f9349c;
        AbstractC0580h.j(objArr, null, i3, objArr.length);
        AbstractC0580h.j(this.f9349c, null, 0, i4);
    }

    private final int l(int i3) {
        Object[] objArr = this.f9349c;
        return i3 >= objArr.length ? i3 - objArr.length : i3;
    }

    private final void m() {
        ((AbstractList) this).modCount++;
    }

    private final void n(int i3, int i4) {
        int iL = l(this.f9348b + (i3 - 1));
        int iL2 = l(this.f9348b + (i4 - 1));
        while (i3 > 0) {
            int i5 = iL + 1;
            int iMin = Math.min(i3, Math.min(i5, iL2 + 1));
            Object[] objArr = this.f9349c;
            int i6 = iL2 - iMin;
            int i7 = iL - iMin;
            AbstractC0583k.f(objArr, objArr, i6 + 1, i7 + 1, i5);
            iL = j(i7);
            iL2 = j(i6);
            i3 -= iMin;
        }
    }

    private final void o(int i3, int i4) {
        int iL = l(this.f9348b + i4);
        int iL2 = l(this.f9348b + i3);
        int size = size();
        while (true) {
            size -= i4;
            if (size <= 0) {
                return;
            }
            Object[] objArr = this.f9349c;
            i4 = Math.min(size, Math.min(objArr.length - iL, objArr.length - iL2));
            Object[] objArr2 = this.f9349c;
            int i5 = iL + i4;
            AbstractC0583k.f(objArr2, objArr2, iL2, iL, i5);
            iL = l(i5);
            iL2 = l(iL2 + i4);
        }
    }

    @Override // i2.AbstractC0576d
    public int a() {
        return this.f9350d;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean add(Object obj) {
        addLast(obj);
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean addAll(Collection collection) {
        t2.j.f(collection, "elements");
        if (collection.isEmpty()) {
            return false;
        }
        m();
        h(size() + collection.size());
        c(l(this.f9348b + size()), collection);
        return true;
    }

    public final void addFirst(Object obj) {
        m();
        h(size() + 1);
        int iF = f(this.f9348b);
        this.f9348b = iF;
        this.f9349c[iF] = obj;
        this.f9350d = size() + 1;
    }

    public final void addLast(Object obj) {
        m();
        h(size() + 1);
        this.f9349c[l(this.f9348b + size())] = obj;
        this.f9350d = size() + 1;
    }

    @Override // i2.AbstractC0576d
    public Object b(int i3) {
        AbstractC0574b.f9337b.a(i3, size());
        if (i3 == AbstractC0586n.h(this)) {
            return removeLast();
        }
        if (i3 == 0) {
            return removeFirst();
        }
        m();
        int iL = l(this.f9348b + i3);
        Object obj = this.f9349c[iL];
        if (i3 < (size() >> 1)) {
            int i4 = this.f9348b;
            if (iL >= i4) {
                Object[] objArr = this.f9349c;
                AbstractC0583k.f(objArr, objArr, i4 + 1, i4, iL);
            } else {
                Object[] objArr2 = this.f9349c;
                AbstractC0583k.f(objArr2, objArr2, 1, 0, iL);
                Object[] objArr3 = this.f9349c;
                objArr3[0] = objArr3[objArr3.length - 1];
                int i5 = this.f9348b;
                AbstractC0583k.f(objArr3, objArr3, i5 + 1, i5, objArr3.length - 1);
            }
            Object[] objArr4 = this.f9349c;
            int i6 = this.f9348b;
            objArr4[i6] = null;
            this.f9348b = i(i6);
        } else {
            int iL2 = l(this.f9348b + AbstractC0586n.h(this));
            if (iL <= iL2) {
                Object[] objArr5 = this.f9349c;
                AbstractC0583k.f(objArr5, objArr5, iL, iL + 1, iL2 + 1);
            } else {
                Object[] objArr6 = this.f9349c;
                AbstractC0583k.f(objArr6, objArr6, iL, iL + 1, objArr6.length);
                Object[] objArr7 = this.f9349c;
                objArr7[objArr7.length - 1] = objArr7[0];
                AbstractC0583k.f(objArr7, objArr7, 0, 1, iL2 + 1);
            }
            this.f9349c[iL2] = null;
        }
        this.f9350d = size() - 1;
        return obj;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public void clear() {
        if (!isEmpty()) {
            m();
            k(this.f9348b, l(this.f9348b + size()));
        }
        this.f9348b = 0;
        this.f9350d = 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean contains(Object obj) {
        return indexOf(obj) != -1;
    }

    @Override // java.util.AbstractList, java.util.List
    public Object get(int i3) {
        AbstractC0574b.f9337b.a(i3, size());
        return this.f9349c[l(this.f9348b + i3)];
    }

    @Override // java.util.AbstractList, java.util.List
    public int indexOf(Object obj) {
        int i3;
        int iL = l(this.f9348b + size());
        int length = this.f9348b;
        if (length < iL) {
            while (length < iL) {
                if (t2.j.b(obj, this.f9349c[length])) {
                    i3 = this.f9348b;
                } else {
                    length++;
                }
            }
            return -1;
        }
        if (length < iL) {
            return -1;
        }
        int length2 = this.f9349c.length;
        while (true) {
            if (length >= length2) {
                for (int i4 = 0; i4 < iL; i4++) {
                    if (t2.j.b(obj, this.f9349c[i4])) {
                        length = i4 + this.f9349c.length;
                        i3 = this.f9348b;
                    }
                }
                return -1;
            }
            if (t2.j.b(obj, this.f9349c[length])) {
                i3 = this.f9348b;
                break;
            }
            length++;
        }
        return length - i3;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean isEmpty() {
        return size() == 0;
    }

    @Override // java.util.AbstractList, java.util.List
    public int lastIndexOf(Object obj) {
        int iR;
        int i3;
        int iL = l(this.f9348b + size());
        int i4 = this.f9348b;
        if (i4 < iL) {
            iR = iL - 1;
            if (i4 <= iR) {
                while (!t2.j.b(obj, this.f9349c[iR])) {
                    if (iR != i4) {
                        iR--;
                    }
                }
                i3 = this.f9348b;
                return iR - i3;
            }
            return -1;
        }
        if (i4 > iL) {
            int i5 = iL - 1;
            while (true) {
                if (-1 >= i5) {
                    iR = AbstractC0580h.r(this.f9349c);
                    int i6 = this.f9348b;
                    if (i6 <= iR) {
                        while (!t2.j.b(obj, this.f9349c[iR])) {
                            if (iR != i6) {
                                iR--;
                            }
                        }
                        i3 = this.f9348b;
                    }
                } else {
                    if (t2.j.b(obj, this.f9349c[i5])) {
                        iR = i5 + this.f9349c.length;
                        i3 = this.f9348b;
                        break;
                    }
                    i5--;
                }
            }
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean remove(Object obj) {
        int iIndexOf = indexOf(obj);
        if (iIndexOf == -1) {
            return false;
        }
        remove(iIndexOf);
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean removeAll(Collection collection) {
        int iL;
        t2.j.f(collection, "elements");
        boolean z3 = false;
        z3 = false;
        z3 = false;
        if (!isEmpty() && this.f9349c.length != 0) {
            int iL2 = l(this.f9348b + size());
            int i3 = this.f9348b;
            if (i3 < iL2) {
                iL = i3;
                while (i3 < iL2) {
                    Object obj = this.f9349c[i3];
                    if (collection.contains(obj)) {
                        z3 = true;
                    } else {
                        this.f9349c[iL] = obj;
                        iL++;
                    }
                    i3++;
                }
                AbstractC0580h.j(this.f9349c, null, iL, iL2);
            } else {
                int length = this.f9349c.length;
                boolean z4 = false;
                int i4 = i3;
                while (i3 < length) {
                    Object[] objArr = this.f9349c;
                    Object obj2 = objArr[i3];
                    objArr[i3] = null;
                    if (collection.contains(obj2)) {
                        z4 = true;
                    } else {
                        this.f9349c[i4] = obj2;
                        i4++;
                    }
                    i3++;
                }
                iL = l(i4);
                for (int i5 = 0; i5 < iL2; i5++) {
                    Object[] objArr2 = this.f9349c;
                    Object obj3 = objArr2[i5];
                    objArr2[i5] = null;
                    if (collection.contains(obj3)) {
                        z4 = true;
                    } else {
                        this.f9349c[iL] = obj3;
                        iL = i(iL);
                    }
                }
                z3 = z4;
            }
            if (z3) {
                m();
                this.f9350d = j(iL - this.f9348b);
            }
        }
        return z3;
    }

    public final Object removeFirst() {
        if (isEmpty()) {
            throw new NoSuchElementException("ArrayDeque is empty.");
        }
        m();
        Object[] objArr = this.f9349c;
        int i3 = this.f9348b;
        Object obj = objArr[i3];
        objArr[i3] = null;
        this.f9348b = i(i3);
        this.f9350d = size() - 1;
        return obj;
    }

    public final Object removeLast() {
        if (isEmpty()) {
            throw new NoSuchElementException("ArrayDeque is empty.");
        }
        m();
        int iL = l(this.f9348b + AbstractC0586n.h(this));
        Object[] objArr = this.f9349c;
        Object obj = objArr[iL];
        objArr[iL] = null;
        this.f9350d = size() - 1;
        return obj;
    }

    @Override // java.util.AbstractList
    protected void removeRange(int i3, int i4) {
        AbstractC0574b.f9337b.c(i3, i4, size());
        int i5 = i4 - i3;
        if (i5 == 0) {
            return;
        }
        if (i5 == size()) {
            clear();
            return;
        }
        if (i5 == 1) {
            remove(i3);
            return;
        }
        m();
        if (i3 < size() - i4) {
            n(i3, i4);
            int iL = l(this.f9348b + i5);
            k(this.f9348b, iL);
            this.f9348b = iL;
        } else {
            o(i3, i4);
            int iL2 = l(this.f9348b + size());
            k(j(iL2 - i5), iL2);
        }
        this.f9350d = size() - i5;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean retainAll(Collection collection) {
        int iL;
        t2.j.f(collection, "elements");
        boolean z3 = false;
        z3 = false;
        z3 = false;
        if (!isEmpty() && this.f9349c.length != 0) {
            int iL2 = l(this.f9348b + size());
            int i3 = this.f9348b;
            if (i3 < iL2) {
                iL = i3;
                while (i3 < iL2) {
                    Object obj = this.f9349c[i3];
                    if (collection.contains(obj)) {
                        this.f9349c[iL] = obj;
                        iL++;
                    } else {
                        z3 = true;
                    }
                    i3++;
                }
                AbstractC0580h.j(this.f9349c, null, iL, iL2);
            } else {
                int length = this.f9349c.length;
                boolean z4 = false;
                int i4 = i3;
                while (i3 < length) {
                    Object[] objArr = this.f9349c;
                    Object obj2 = objArr[i3];
                    objArr[i3] = null;
                    if (collection.contains(obj2)) {
                        this.f9349c[i4] = obj2;
                        i4++;
                    } else {
                        z4 = true;
                    }
                    i3++;
                }
                iL = l(i4);
                for (int i5 = 0; i5 < iL2; i5++) {
                    Object[] objArr2 = this.f9349c;
                    Object obj3 = objArr2[i5];
                    objArr2[i5] = null;
                    if (collection.contains(obj3)) {
                        this.f9349c[iL] = obj3;
                        iL = i(iL);
                    } else {
                        z4 = true;
                    }
                }
                z3 = z4;
            }
            if (z3) {
                m();
                this.f9350d = j(iL - this.f9348b);
            }
        }
        return z3;
    }

    @Override // java.util.AbstractList, java.util.List
    public Object set(int i3, Object obj) {
        AbstractC0574b.f9337b.a(i3, size());
        int iL = l(this.f9348b + i3);
        Object[] objArr = this.f9349c;
        Object obj2 = objArr[iL];
        objArr[iL] = obj;
        return obj2;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public Object[] toArray(Object[] objArr) {
        t2.j.f(objArr, "array");
        if (objArr.length < size()) {
            objArr = AbstractC0581i.a(objArr, size());
        }
        int iL = l(this.f9348b + size());
        int i3 = this.f9348b;
        if (i3 < iL) {
            AbstractC0583k.h(this.f9349c, objArr, 0, i3, iL, 2, null);
        } else if (!isEmpty()) {
            Object[] objArr2 = this.f9349c;
            AbstractC0583k.f(objArr2, objArr, 0, this.f9348b, objArr2.length);
            Object[] objArr3 = this.f9349c;
            AbstractC0583k.f(objArr3, objArr, objArr3.length - this.f9348b, 0, iL);
        }
        return o.c(size(), objArr);
    }

    @Override // java.util.AbstractList, java.util.List
    public void add(int i3, Object obj) {
        AbstractC0574b.f9337b.b(i3, size());
        if (i3 == size()) {
            addLast(obj);
            return;
        }
        if (i3 == 0) {
            addFirst(obj);
            return;
        }
        m();
        h(size() + 1);
        int iL = l(this.f9348b + i3);
        if (i3 < ((size() + 1) >> 1)) {
            int iF = f(iL);
            int iF2 = f(this.f9348b);
            int i4 = this.f9348b;
            if (iF >= i4) {
                Object[] objArr = this.f9349c;
                objArr[iF2] = objArr[i4];
                AbstractC0583k.f(objArr, objArr, i4, i4 + 1, iF + 1);
            } else {
                Object[] objArr2 = this.f9349c;
                AbstractC0583k.f(objArr2, objArr2, i4 - 1, i4, objArr2.length);
                Object[] objArr3 = this.f9349c;
                objArr3[objArr3.length - 1] = objArr3[0];
                AbstractC0583k.f(objArr3, objArr3, 0, 1, iF + 1);
            }
            this.f9349c[iF] = obj;
            this.f9348b = iF2;
        } else {
            int iL2 = l(this.f9348b + size());
            if (iL < iL2) {
                Object[] objArr4 = this.f9349c;
                AbstractC0583k.f(objArr4, objArr4, iL + 1, iL, iL2);
            } else {
                Object[] objArr5 = this.f9349c;
                AbstractC0583k.f(objArr5, objArr5, 1, 0, iL2);
                Object[] objArr6 = this.f9349c;
                objArr6[0] = objArr6[objArr6.length - 1];
                AbstractC0583k.f(objArr6, objArr6, iL + 1, iL, objArr6.length - 1);
            }
            this.f9349c[iL] = obj;
        }
        this.f9350d = size() + 1;
    }

    @Override // java.util.AbstractList, java.util.List
    public boolean addAll(int i3, Collection collection) {
        t2.j.f(collection, "elements");
        AbstractC0574b.f9337b.b(i3, size());
        if (collection.isEmpty()) {
            return false;
        }
        if (i3 == size()) {
            return addAll(collection);
        }
        m();
        h(size() + collection.size());
        int iL = l(this.f9348b + size());
        int iL2 = l(this.f9348b + i3);
        int size = collection.size();
        if (i3 < ((size() + 1) >> 1)) {
            int i4 = this.f9348b;
            int length = i4 - size;
            if (iL2 < i4) {
                Object[] objArr = this.f9349c;
                AbstractC0583k.f(objArr, objArr, length, i4, objArr.length);
                if (size >= iL2) {
                    Object[] objArr2 = this.f9349c;
                    AbstractC0583k.f(objArr2, objArr2, objArr2.length - size, 0, iL2);
                } else {
                    Object[] objArr3 = this.f9349c;
                    AbstractC0583k.f(objArr3, objArr3, objArr3.length - size, 0, size);
                    Object[] objArr4 = this.f9349c;
                    AbstractC0583k.f(objArr4, objArr4, 0, size, iL2);
                }
            } else if (length >= 0) {
                Object[] objArr5 = this.f9349c;
                AbstractC0583k.f(objArr5, objArr5, length, i4, iL2);
            } else {
                Object[] objArr6 = this.f9349c;
                length += objArr6.length;
                int i5 = iL2 - i4;
                int length2 = objArr6.length - length;
                if (length2 >= i5) {
                    AbstractC0583k.f(objArr6, objArr6, length, i4, iL2);
                } else {
                    AbstractC0583k.f(objArr6, objArr6, length, i4, i4 + length2);
                    Object[] objArr7 = this.f9349c;
                    AbstractC0583k.f(objArr7, objArr7, 0, this.f9348b + length2, iL2);
                }
            }
            this.f9348b = length;
            c(j(iL2 - size), collection);
        } else {
            int i6 = iL2 + size;
            if (iL2 < iL) {
                int i7 = size + iL;
                Object[] objArr8 = this.f9349c;
                if (i7 <= objArr8.length) {
                    AbstractC0583k.f(objArr8, objArr8, i6, iL2, iL);
                } else if (i6 >= objArr8.length) {
                    AbstractC0583k.f(objArr8, objArr8, i6 - objArr8.length, iL2, iL);
                } else {
                    int length3 = iL - (i7 - objArr8.length);
                    AbstractC0583k.f(objArr8, objArr8, 0, length3, iL);
                    Object[] objArr9 = this.f9349c;
                    AbstractC0583k.f(objArr9, objArr9, i6, iL2, length3);
                }
            } else {
                Object[] objArr10 = this.f9349c;
                AbstractC0583k.f(objArr10, objArr10, size, 0, iL);
                Object[] objArr11 = this.f9349c;
                if (i6 >= objArr11.length) {
                    AbstractC0583k.f(objArr11, objArr11, i6 - objArr11.length, iL2, objArr11.length);
                } else {
                    AbstractC0583k.f(objArr11, objArr11, 0, objArr11.length - size, objArr11.length);
                    Object[] objArr12 = this.f9349c;
                    AbstractC0583k.f(objArr12, objArr12, i6, iL2, objArr12.length - size);
                }
            }
            c(iL2, collection);
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public Object[] toArray() {
        return toArray(new Object[size()]);
    }
}
