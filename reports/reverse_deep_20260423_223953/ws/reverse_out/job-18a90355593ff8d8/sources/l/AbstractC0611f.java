package l;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

/* JADX INFO: renamed from: l.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
abstract class AbstractC0611f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    b f9453a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    c f9454b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    e f9455c;

    /* JADX INFO: renamed from: l.f$a */
    final class a implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final int f9456a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f9457b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        int f9458c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        boolean f9459d = false;

        a(int i3) {
            this.f9456a = i3;
            this.f9457b = AbstractC0611f.this.d();
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f9458c < this.f9457b;
        }

        @Override // java.util.Iterator
        public Object next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            Object objB = AbstractC0611f.this.b(this.f9458c, this.f9456a);
            this.f9458c++;
            this.f9459d = true;
            return objB;
        }

        @Override // java.util.Iterator
        public void remove() {
            if (!this.f9459d) {
                throw new IllegalStateException();
            }
            int i3 = this.f9458c - 1;
            this.f9458c = i3;
            this.f9457b--;
            this.f9459d = false;
            AbstractC0611f.this.h(i3);
        }
    }

    /* JADX INFO: renamed from: l.f$b */
    final class b implements Set {
        b() {
        }

        @Override // java.util.Set, java.util.Collection
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public boolean add(Map.Entry entry) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean addAll(Collection collection) {
            int iD = AbstractC0611f.this.d();
            Iterator it = collection.iterator();
            while (it.hasNext()) {
                Map.Entry entry = (Map.Entry) it.next();
                AbstractC0611f.this.g(entry.getKey(), entry.getValue());
            }
            return iD != AbstractC0611f.this.d();
        }

        @Override // java.util.Set, java.util.Collection
        public void clear() {
            AbstractC0611f.this.a();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean contains(Object obj) {
            if (!(obj instanceof Map.Entry)) {
                return false;
            }
            Map.Entry entry = (Map.Entry) obj;
            int iE = AbstractC0611f.this.e(entry.getKey());
            if (iE < 0) {
                return false;
            }
            return AbstractC0608c.c(AbstractC0611f.this.b(iE, 1), entry.getValue());
        }

        @Override // java.util.Set, java.util.Collection
        public boolean containsAll(Collection collection) {
            Iterator it = collection.iterator();
            while (it.hasNext()) {
                if (!contains(it.next())) {
                    return false;
                }
            }
            return true;
        }

        @Override // java.util.Set, java.util.Collection
        public boolean equals(Object obj) {
            return AbstractC0611f.k(this, obj);
        }

        @Override // java.util.Set, java.util.Collection
        public int hashCode() {
            int iHashCode = 0;
            for (int iD = AbstractC0611f.this.d() - 1; iD >= 0; iD--) {
                Object objB = AbstractC0611f.this.b(iD, 0);
                Object objB2 = AbstractC0611f.this.b(iD, 1);
                iHashCode += (objB == null ? 0 : objB.hashCode()) ^ (objB2 == null ? 0 : objB2.hashCode());
            }
            return iHashCode;
        }

        @Override // java.util.Set, java.util.Collection
        public boolean isEmpty() {
            return AbstractC0611f.this.d() == 0;
        }

        @Override // java.util.Set, java.util.Collection, java.lang.Iterable
        public Iterator iterator() {
            return AbstractC0611f.this.new d();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean remove(Object obj) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean removeAll(Collection collection) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean retainAll(Collection collection) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public int size() {
            return AbstractC0611f.this.d();
        }

        @Override // java.util.Set, java.util.Collection
        public Object[] toArray() {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public Object[] toArray(Object[] objArr) {
            throw new UnsupportedOperationException();
        }
    }

    /* JADX INFO: renamed from: l.f$c */
    final class c implements Set {
        c() {
        }

        @Override // java.util.Set, java.util.Collection
        public boolean add(Object obj) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean addAll(Collection collection) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Set, java.util.Collection
        public void clear() {
            AbstractC0611f.this.a();
        }

        @Override // java.util.Set, java.util.Collection
        public boolean contains(Object obj) {
            return AbstractC0611f.this.e(obj) >= 0;
        }

        @Override // java.util.Set, java.util.Collection
        public boolean containsAll(Collection collection) {
            return AbstractC0611f.j(AbstractC0611f.this.c(), collection);
        }

        @Override // java.util.Set, java.util.Collection
        public boolean equals(Object obj) {
            return AbstractC0611f.k(this, obj);
        }

        @Override // java.util.Set, java.util.Collection
        public int hashCode() {
            int iHashCode = 0;
            for (int iD = AbstractC0611f.this.d() - 1; iD >= 0; iD--) {
                Object objB = AbstractC0611f.this.b(iD, 0);
                iHashCode += objB == null ? 0 : objB.hashCode();
            }
            return iHashCode;
        }

        @Override // java.util.Set, java.util.Collection
        public boolean isEmpty() {
            return AbstractC0611f.this.d() == 0;
        }

        @Override // java.util.Set, java.util.Collection, java.lang.Iterable
        public Iterator iterator() {
            return AbstractC0611f.this.new a(0);
        }

        @Override // java.util.Set, java.util.Collection
        public boolean remove(Object obj) {
            int iE = AbstractC0611f.this.e(obj);
            if (iE < 0) {
                return false;
            }
            AbstractC0611f.this.h(iE);
            return true;
        }

        @Override // java.util.Set, java.util.Collection
        public boolean removeAll(Collection collection) {
            return AbstractC0611f.o(AbstractC0611f.this.c(), collection);
        }

        @Override // java.util.Set, java.util.Collection
        public boolean retainAll(Collection collection) {
            return AbstractC0611f.p(AbstractC0611f.this.c(), collection);
        }

        @Override // java.util.Set, java.util.Collection
        public int size() {
            return AbstractC0611f.this.d();
        }

        @Override // java.util.Set, java.util.Collection
        public Object[] toArray() {
            return AbstractC0611f.this.q(0);
        }

        @Override // java.util.Set, java.util.Collection
        public Object[] toArray(Object[] objArr) {
            return AbstractC0611f.this.r(objArr, 0);
        }
    }

    /* JADX INFO: renamed from: l.f$d */
    final class d implements Iterator, Map.Entry {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        int f9463a;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        boolean f9465c = false;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f9464b = -1;

        d() {
            this.f9463a = AbstractC0611f.this.d() - 1;
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Map.Entry next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            this.f9464b++;
            this.f9465c = true;
            return this;
        }

        @Override // java.util.Map.Entry
        public boolean equals(Object obj) {
            if (!this.f9465c) {
                throw new IllegalStateException("This container does not support retaining Map.Entry objects");
            }
            if (!(obj instanceof Map.Entry)) {
                return false;
            }
            Map.Entry entry = (Map.Entry) obj;
            return AbstractC0608c.c(entry.getKey(), AbstractC0611f.this.b(this.f9464b, 0)) && AbstractC0608c.c(entry.getValue(), AbstractC0611f.this.b(this.f9464b, 1));
        }

        @Override // java.util.Map.Entry
        public Object getKey() {
            if (this.f9465c) {
                return AbstractC0611f.this.b(this.f9464b, 0);
            }
            throw new IllegalStateException("This container does not support retaining Map.Entry objects");
        }

        @Override // java.util.Map.Entry
        public Object getValue() {
            if (this.f9465c) {
                return AbstractC0611f.this.b(this.f9464b, 1);
            }
            throw new IllegalStateException("This container does not support retaining Map.Entry objects");
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f9464b < this.f9463a;
        }

        @Override // java.util.Map.Entry
        public int hashCode() {
            if (!this.f9465c) {
                throw new IllegalStateException("This container does not support retaining Map.Entry objects");
            }
            Object objB = AbstractC0611f.this.b(this.f9464b, 0);
            Object objB2 = AbstractC0611f.this.b(this.f9464b, 1);
            return (objB == null ? 0 : objB.hashCode()) ^ (objB2 != null ? objB2.hashCode() : 0);
        }

        @Override // java.util.Iterator
        public void remove() {
            if (!this.f9465c) {
                throw new IllegalStateException();
            }
            AbstractC0611f.this.h(this.f9464b);
            this.f9464b--;
            this.f9463a--;
            this.f9465c = false;
        }

        @Override // java.util.Map.Entry
        public Object setValue(Object obj) {
            if (this.f9465c) {
                return AbstractC0611f.this.i(this.f9464b, obj);
            }
            throw new IllegalStateException("This container does not support retaining Map.Entry objects");
        }

        public String toString() {
            return getKey() + "=" + getValue();
        }
    }

    /* JADX INFO: renamed from: l.f$e */
    final class e implements Collection {
        e() {
        }

        @Override // java.util.Collection
        public boolean add(Object obj) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Collection
        public boolean addAll(Collection collection) {
            throw new UnsupportedOperationException();
        }

        @Override // java.util.Collection
        public void clear() {
            AbstractC0611f.this.a();
        }

        @Override // java.util.Collection
        public boolean contains(Object obj) {
            return AbstractC0611f.this.f(obj) >= 0;
        }

        @Override // java.util.Collection
        public boolean containsAll(Collection collection) {
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
            return AbstractC0611f.this.d() == 0;
        }

        @Override // java.util.Collection, java.lang.Iterable
        public Iterator iterator() {
            return AbstractC0611f.this.new a(1);
        }

        @Override // java.util.Collection
        public boolean remove(Object obj) {
            int iF = AbstractC0611f.this.f(obj);
            if (iF < 0) {
                return false;
            }
            AbstractC0611f.this.h(iF);
            return true;
        }

        @Override // java.util.Collection
        public boolean removeAll(Collection collection) {
            int iD = AbstractC0611f.this.d();
            int i3 = 0;
            boolean z3 = false;
            while (i3 < iD) {
                if (collection.contains(AbstractC0611f.this.b(i3, 1))) {
                    AbstractC0611f.this.h(i3);
                    i3--;
                    iD--;
                    z3 = true;
                }
                i3++;
            }
            return z3;
        }

        @Override // java.util.Collection
        public boolean retainAll(Collection collection) {
            int iD = AbstractC0611f.this.d();
            int i3 = 0;
            boolean z3 = false;
            while (i3 < iD) {
                if (!collection.contains(AbstractC0611f.this.b(i3, 1))) {
                    AbstractC0611f.this.h(i3);
                    i3--;
                    iD--;
                    z3 = true;
                }
                i3++;
            }
            return z3;
        }

        @Override // java.util.Collection
        public int size() {
            return AbstractC0611f.this.d();
        }

        @Override // java.util.Collection
        public Object[] toArray() {
            return AbstractC0611f.this.q(1);
        }

        @Override // java.util.Collection
        public Object[] toArray(Object[] objArr) {
            return AbstractC0611f.this.r(objArr, 1);
        }
    }

    AbstractC0611f() {
    }

    public static boolean j(Map map, Collection collection) {
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            if (!map.containsKey(it.next())) {
                return false;
            }
        }
        return true;
    }

    public static boolean k(Set set, Object obj) {
        if (set == obj) {
            return true;
        }
        if (obj instanceof Set) {
            Set set2 = (Set) obj;
            try {
                if (set.size() == set2.size()) {
                    if (set.containsAll(set2)) {
                        return true;
                    }
                }
                return false;
            } catch (ClassCastException | NullPointerException unused) {
            }
        }
        return false;
    }

    public static boolean o(Map map, Collection collection) {
        int size = map.size();
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            map.remove(it.next());
        }
        return size != map.size();
    }

    public static boolean p(Map map, Collection collection) {
        int size = map.size();
        Iterator it = map.keySet().iterator();
        while (it.hasNext()) {
            if (!collection.contains(it.next())) {
                it.remove();
            }
        }
        return size != map.size();
    }

    protected abstract void a();

    protected abstract Object b(int i3, int i4);

    protected abstract Map c();

    protected abstract int d();

    protected abstract int e(Object obj);

    protected abstract int f(Object obj);

    protected abstract void g(Object obj, Object obj2);

    protected abstract void h(int i3);

    protected abstract Object i(int i3, Object obj);

    public Set l() {
        if (this.f9453a == null) {
            this.f9453a = new b();
        }
        return this.f9453a;
    }

    public Set m() {
        if (this.f9454b == null) {
            this.f9454b = new c();
        }
        return this.f9454b;
    }

    public Collection n() {
        if (this.f9455c == null) {
            this.f9455c = new e();
        }
        return this.f9455c;
    }

    public Object[] q(int i3) {
        int iD = d();
        Object[] objArr = new Object[iD];
        for (int i4 = 0; i4 < iD; i4++) {
            objArr[i4] = b(i4, i3);
        }
        return objArr;
    }

    public Object[] r(Object[] objArr, int i3) {
        int iD = d();
        if (objArr.length < iD) {
            objArr = (Object[]) Array.newInstance(objArr.getClass().getComponentType(), iD);
        }
        for (int i4 = 0; i4 < iD; i4++) {
            objArr[i4] = b(i4, i3);
        }
        if (objArr.length > iD) {
            objArr[iD] = null;
        }
        return objArr;
    }
}
