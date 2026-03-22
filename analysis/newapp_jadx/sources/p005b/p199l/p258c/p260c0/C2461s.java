package p005b.p199l.p258c.p260c0;

import java.io.Serializable;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;

/* renamed from: b.l.c.c0.s */
/* loaded from: classes2.dex */
public final class C2461s<K, V> extends AbstractMap<K, V> implements Serializable {

    /* renamed from: c */
    public static final Comparator<Comparable> f6610c = new a();

    /* renamed from: e */
    public Comparator<? super K> f6611e;

    /* renamed from: f */
    public e<K, V> f6612f;

    /* renamed from: g */
    public int f6613g;

    /* renamed from: h */
    public int f6614h;

    /* renamed from: i */
    public final e<K, V> f6615i;

    /* renamed from: j */
    public C2461s<K, V>.b f6616j;

    /* renamed from: k */
    public C2461s<K, V>.c f6617k;

    /* renamed from: b.l.c.c0.s$a */
    public static class a implements Comparator<Comparable> {
        @Override // java.util.Comparator
        public int compare(Comparable comparable, Comparable comparable2) {
            return comparable.compareTo(comparable2);
        }
    }

    /* renamed from: b.l.c.c0.s$b */
    public class b extends AbstractSet<Map.Entry<K, V>> {

        /* renamed from: b.l.c.c0.s$b$a */
        public class a extends C2461s<K, V>.d<Map.Entry<K, V>> {
            public a(b bVar) {
                super();
            }

            @Override // java.util.Iterator
            public Object next() {
                return m2823a();
            }
        }

        public b() {
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public void clear() {
            C2461s.this.clear();
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public boolean contains(Object obj) {
            return (obj instanceof Map.Entry) && C2461s.this.m2816b((Map.Entry) obj) != null;
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
        public Iterator<Map.Entry<K, V>> iterator() {
            return new a(this);
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public boolean remove(Object obj) {
            e<K, V> m2816b;
            if (!(obj instanceof Map.Entry) || (m2816b = C2461s.this.m2816b((Map.Entry) obj)) == null) {
                return false;
            }
            C2461s.this.m2819e(m2816b, true);
            return true;
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public int size() {
            return C2461s.this.f6613g;
        }
    }

    /* renamed from: b.l.c.c0.s$c */
    public final class c extends AbstractSet<K> {

        /* renamed from: b.l.c.c0.s$c$a */
        public class a extends C2461s<K, V>.d<K> {
            public a(c cVar) {
                super();
            }

            @Override // java.util.Iterator
            public K next() {
                return m2823a().f6629i;
            }
        }

        public c() {
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public void clear() {
            C2461s.this.clear();
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public boolean contains(Object obj) {
            return C2461s.this.m2817c(obj) != null;
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
        public Iterator<K> iterator() {
            return new a(this);
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public boolean remove(Object obj) {
            C2461s c2461s = C2461s.this;
            e<K, V> m2817c = c2461s.m2817c(obj);
            if (m2817c != null) {
                c2461s.m2819e(m2817c, true);
            }
            return m2817c != null;
        }

        @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
        public int size() {
            return C2461s.this.f6613g;
        }
    }

    /* renamed from: b.l.c.c0.s$d */
    public abstract class d<T> implements Iterator<T> {

        /* renamed from: c */
        public e<K, V> f6620c;

        /* renamed from: e */
        public e<K, V> f6621e = null;

        /* renamed from: f */
        public int f6622f;

        public d() {
            this.f6620c = C2461s.this.f6615i.f6627g;
            this.f6622f = C2461s.this.f6614h;
        }

        /* renamed from: a */
        public final e<K, V> m2823a() {
            e<K, V> eVar = this.f6620c;
            C2461s c2461s = C2461s.this;
            if (eVar == c2461s.f6615i) {
                throw new NoSuchElementException();
            }
            if (c2461s.f6614h != this.f6622f) {
                throw new ConcurrentModificationException();
            }
            this.f6620c = eVar.f6627g;
            this.f6621e = eVar;
            return eVar;
        }

        @Override // java.util.Iterator
        public final boolean hasNext() {
            return this.f6620c != C2461s.this.f6615i;
        }

        @Override // java.util.Iterator
        public final void remove() {
            e<K, V> eVar = this.f6621e;
            if (eVar == null) {
                throw new IllegalStateException();
            }
            C2461s.this.m2819e(eVar, true);
            this.f6621e = null;
            this.f6622f = C2461s.this.f6614h;
        }
    }

    public C2461s() {
        Comparator<Comparable> comparator = f6610c;
        this.f6613g = 0;
        this.f6614h = 0;
        this.f6615i = new e<>();
        this.f6611e = comparator;
    }

    private Object writeReplace() {
        return new LinkedHashMap(this);
    }

    /* renamed from: a */
    public e<K, V> m2815a(K k2, boolean z) {
        int i2;
        e<K, V> eVar;
        Comparator<? super K> comparator = this.f6611e;
        e<K, V> eVar2 = this.f6612f;
        if (eVar2 != null) {
            Comparable comparable = comparator == f6610c ? (Comparable) k2 : null;
            while (true) {
                i2 = comparable != null ? comparable.compareTo(eVar2.f6629i) : comparator.compare(k2, eVar2.f6629i);
                if (i2 == 0) {
                    return eVar2;
                }
                e<K, V> eVar3 = i2 < 0 ? eVar2.f6625e : eVar2.f6626f;
                if (eVar3 == null) {
                    break;
                }
                eVar2 = eVar3;
            }
        } else {
            i2 = 0;
        }
        if (!z) {
            return null;
        }
        e<K, V> eVar4 = this.f6615i;
        if (eVar2 != null) {
            eVar = new e<>(eVar2, k2, eVar4, eVar4.f6628h);
            if (i2 < 0) {
                eVar2.f6625e = eVar;
            } else {
                eVar2.f6626f = eVar;
            }
            m2818d(eVar2, true);
        } else {
            if (comparator == f6610c && !(k2 instanceof Comparable)) {
                throw new ClassCastException(k2.getClass().getName() + " is not Comparable");
            }
            eVar = new e<>(eVar2, k2, eVar4, eVar4.f6628h);
            this.f6612f = eVar;
        }
        this.f6613g++;
        this.f6614h++;
        return eVar;
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x0020, code lost:
    
        if ((r3 == r5 || (r3 != null && r3.equals(r5))) != false) goto L15;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p258c.p260c0.C2461s.e<K, V> m2816b(java.util.Map.Entry<?, ?> r5) {
        /*
            r4 = this;
            java.lang.Object r0 = r5.getKey()
            b.l.c.c0.s$e r0 = r4.m2817c(r0)
            r1 = 1
            r2 = 0
            if (r0 == 0) goto L23
            V r3 = r0.f6630j
            java.lang.Object r5 = r5.getValue()
            if (r3 == r5) goto L1f
            if (r3 == 0) goto L1d
            boolean r5 = r3.equals(r5)
            if (r5 == 0) goto L1d
            goto L1f
        L1d:
            r5 = 0
            goto L20
        L1f:
            r5 = 1
        L20:
            if (r5 == 0) goto L23
            goto L24
        L23:
            r1 = 0
        L24:
            if (r1 == 0) goto L27
            goto L28
        L27:
            r0 = 0
        L28:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.p260c0.C2461s.m2816b(java.util.Map$Entry):b.l.c.c0.s$e");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: c */
    public e<K, V> m2817c(Object obj) {
        if (obj == 0) {
            return null;
        }
        try {
            return m2815a(obj, false);
        } catch (ClassCastException unused) {
            return null;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public void clear() {
        this.f6612f = null;
        this.f6613g = 0;
        this.f6614h++;
        e<K, V> eVar = this.f6615i;
        eVar.f6628h = eVar;
        eVar.f6627g = eVar;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public boolean containsKey(Object obj) {
        return m2817c(obj) != null;
    }

    /* renamed from: d */
    public final void m2818d(e<K, V> eVar, boolean z) {
        while (eVar != null) {
            e<K, V> eVar2 = eVar.f6625e;
            e<K, V> eVar3 = eVar.f6626f;
            int i2 = eVar2 != null ? eVar2.f6631k : 0;
            int i3 = eVar3 != null ? eVar3.f6631k : 0;
            int i4 = i2 - i3;
            if (i4 == -2) {
                e<K, V> eVar4 = eVar3.f6625e;
                e<K, V> eVar5 = eVar3.f6626f;
                int i5 = (eVar4 != null ? eVar4.f6631k : 0) - (eVar5 != null ? eVar5.f6631k : 0);
                if (i5 == -1 || (i5 == 0 && !z)) {
                    m2821g(eVar);
                } else {
                    m2822h(eVar3);
                    m2821g(eVar);
                }
                if (z) {
                    return;
                }
            } else if (i4 == 2) {
                e<K, V> eVar6 = eVar2.f6625e;
                e<K, V> eVar7 = eVar2.f6626f;
                int i6 = (eVar6 != null ? eVar6.f6631k : 0) - (eVar7 != null ? eVar7.f6631k : 0);
                if (i6 == 1 || (i6 == 0 && !z)) {
                    m2822h(eVar);
                } else {
                    m2821g(eVar2);
                    m2822h(eVar);
                }
                if (z) {
                    return;
                }
            } else if (i4 == 0) {
                eVar.f6631k = i2 + 1;
                if (z) {
                    return;
                }
            } else {
                eVar.f6631k = Math.max(i2, i3) + 1;
                if (!z) {
                    return;
                }
            }
            eVar = eVar.f6624c;
        }
    }

    /* renamed from: e */
    public void m2819e(e<K, V> eVar, boolean z) {
        e<K, V> eVar2;
        e<K, V> eVar3;
        int i2;
        if (z) {
            e<K, V> eVar4 = eVar.f6628h;
            eVar4.f6627g = eVar.f6627g;
            eVar.f6627g.f6628h = eVar4;
        }
        e<K, V> eVar5 = eVar.f6625e;
        e<K, V> eVar6 = eVar.f6626f;
        e<K, V> eVar7 = eVar.f6624c;
        int i3 = 0;
        if (eVar5 == null || eVar6 == null) {
            if (eVar5 != null) {
                m2820f(eVar, eVar5);
                eVar.f6625e = null;
            } else if (eVar6 != null) {
                m2820f(eVar, eVar6);
                eVar.f6626f = null;
            } else {
                m2820f(eVar, null);
            }
            m2818d(eVar7, false);
            this.f6613g--;
            this.f6614h++;
            return;
        }
        if (eVar5.f6631k > eVar6.f6631k) {
            e<K, V> eVar8 = eVar5.f6626f;
            while (true) {
                e<K, V> eVar9 = eVar8;
                eVar3 = eVar5;
                eVar5 = eVar9;
                if (eVar5 == null) {
                    break;
                } else {
                    eVar8 = eVar5.f6626f;
                }
            }
        } else {
            e<K, V> eVar10 = eVar6.f6625e;
            while (true) {
                eVar2 = eVar6;
                eVar6 = eVar10;
                if (eVar6 == null) {
                    break;
                } else {
                    eVar10 = eVar6.f6625e;
                }
            }
            eVar3 = eVar2;
        }
        m2819e(eVar3, false);
        e<K, V> eVar11 = eVar.f6625e;
        if (eVar11 != null) {
            i2 = eVar11.f6631k;
            eVar3.f6625e = eVar11;
            eVar11.f6624c = eVar3;
            eVar.f6625e = null;
        } else {
            i2 = 0;
        }
        e<K, V> eVar12 = eVar.f6626f;
        if (eVar12 != null) {
            i3 = eVar12.f6631k;
            eVar3.f6626f = eVar12;
            eVar12.f6624c = eVar3;
            eVar.f6626f = null;
        }
        eVar3.f6631k = Math.max(i2, i3) + 1;
        m2820f(eVar, eVar3);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public Set<Map.Entry<K, V>> entrySet() {
        C2461s<K, V>.b bVar = this.f6616j;
        if (bVar != null) {
            return bVar;
        }
        C2461s<K, V>.b bVar2 = new b();
        this.f6616j = bVar2;
        return bVar2;
    }

    /* renamed from: f */
    public final void m2820f(e<K, V> eVar, e<K, V> eVar2) {
        e<K, V> eVar3 = eVar.f6624c;
        eVar.f6624c = null;
        if (eVar2 != null) {
            eVar2.f6624c = eVar3;
        }
        if (eVar3 == null) {
            this.f6612f = eVar2;
        } else if (eVar3.f6625e == eVar) {
            eVar3.f6625e = eVar2;
        } else {
            eVar3.f6626f = eVar2;
        }
    }

    /* renamed from: g */
    public final void m2821g(e<K, V> eVar) {
        e<K, V> eVar2 = eVar.f6625e;
        e<K, V> eVar3 = eVar.f6626f;
        e<K, V> eVar4 = eVar3.f6625e;
        e<K, V> eVar5 = eVar3.f6626f;
        eVar.f6626f = eVar4;
        if (eVar4 != null) {
            eVar4.f6624c = eVar;
        }
        m2820f(eVar, eVar3);
        eVar3.f6625e = eVar;
        eVar.f6624c = eVar3;
        int max = Math.max(eVar2 != null ? eVar2.f6631k : 0, eVar4 != null ? eVar4.f6631k : 0) + 1;
        eVar.f6631k = max;
        eVar3.f6631k = Math.max(max, eVar5 != null ? eVar5.f6631k : 0) + 1;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public V get(Object obj) {
        e<K, V> m2817c = m2817c(obj);
        if (m2817c != null) {
            return m2817c.f6630j;
        }
        return null;
    }

    /* renamed from: h */
    public final void m2822h(e<K, V> eVar) {
        e<K, V> eVar2 = eVar.f6625e;
        e<K, V> eVar3 = eVar.f6626f;
        e<K, V> eVar4 = eVar2.f6625e;
        e<K, V> eVar5 = eVar2.f6626f;
        eVar.f6625e = eVar5;
        if (eVar5 != null) {
            eVar5.f6624c = eVar;
        }
        m2820f(eVar, eVar2);
        eVar2.f6626f = eVar;
        eVar.f6624c = eVar2;
        int max = Math.max(eVar3 != null ? eVar3.f6631k : 0, eVar5 != null ? eVar5.f6631k : 0) + 1;
        eVar.f6631k = max;
        eVar2.f6631k = Math.max(max, eVar4 != null ? eVar4.f6631k : 0) + 1;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public Set<K> keySet() {
        C2461s<K, V>.c cVar = this.f6617k;
        if (cVar != null) {
            return cVar;
        }
        C2461s<K, V>.c cVar2 = new c();
        this.f6617k = cVar2;
        return cVar2;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public V put(K k2, V v) {
        Objects.requireNonNull(k2, "key == null");
        e<K, V> m2815a = m2815a(k2, true);
        V v2 = m2815a.f6630j;
        m2815a.f6630j = v;
        return v2;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public V remove(Object obj) {
        e<K, V> m2817c = m2817c(obj);
        if (m2817c != null) {
            m2819e(m2817c, true);
        }
        if (m2817c != null) {
            return m2817c.f6630j;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public int size() {
        return this.f6613g;
    }

    /* renamed from: b.l.c.c0.s$e */
    public static final class e<K, V> implements Map.Entry<K, V> {

        /* renamed from: c */
        public e<K, V> f6624c;

        /* renamed from: e */
        public e<K, V> f6625e;

        /* renamed from: f */
        public e<K, V> f6626f;

        /* renamed from: g */
        public e<K, V> f6627g;

        /* renamed from: h */
        public e<K, V> f6628h;

        /* renamed from: i */
        public final K f6629i;

        /* renamed from: j */
        public V f6630j;

        /* renamed from: k */
        public int f6631k;

        public e() {
            this.f6629i = null;
            this.f6628h = this;
            this.f6627g = this;
        }

        @Override // java.util.Map.Entry
        public boolean equals(Object obj) {
            if (!(obj instanceof Map.Entry)) {
                return false;
            }
            Map.Entry entry = (Map.Entry) obj;
            K k2 = this.f6629i;
            if (k2 == null) {
                if (entry.getKey() != null) {
                    return false;
                }
            } else if (!k2.equals(entry.getKey())) {
                return false;
            }
            V v = this.f6630j;
            if (v == null) {
                if (entry.getValue() != null) {
                    return false;
                }
            } else if (!v.equals(entry.getValue())) {
                return false;
            }
            return true;
        }

        @Override // java.util.Map.Entry
        public K getKey() {
            return this.f6629i;
        }

        @Override // java.util.Map.Entry
        public V getValue() {
            return this.f6630j;
        }

        @Override // java.util.Map.Entry
        public int hashCode() {
            K k2 = this.f6629i;
            int hashCode = k2 == null ? 0 : k2.hashCode();
            V v = this.f6630j;
            return hashCode ^ (v != null ? v.hashCode() : 0);
        }

        @Override // java.util.Map.Entry
        public V setValue(V v) {
            V v2 = this.f6630j;
            this.f6630j = v;
            return v2;
        }

        public String toString() {
            return this.f6629i + "=" + this.f6630j;
        }

        public e(e<K, V> eVar, K k2, e<K, V> eVar2, e<K, V> eVar3) {
            this.f6624c = eVar;
            this.f6629i = k2;
            this.f6631k = 1;
            this.f6627g = eVar2;
            this.f6628h = eVar3;
            eVar3.f6627g = this;
            eVar2.f6628h = this;
        }
    }
}
