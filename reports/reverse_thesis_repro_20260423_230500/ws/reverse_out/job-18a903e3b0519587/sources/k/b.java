package k;

import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;

/* JADX INFO: loaded from: classes.dex */
public class b implements Iterable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    c f9397b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private c f9398c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final WeakHashMap f9399d = new WeakHashMap();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f9400e = 0;

    static class a extends e {
        a(c cVar, c cVar2) {
            super(cVar, cVar2);
        }

        @Override // k.b.e
        c b(c cVar) {
            return cVar.f9404d;
        }

        @Override // k.b.e
        c c(c cVar) {
            return cVar.f9403c;
        }
    }

    /* JADX INFO: renamed from: k.b$b, reason: collision with other inner class name */
    private static class C0136b extends e {
        C0136b(c cVar, c cVar2) {
            super(cVar, cVar2);
        }

        @Override // k.b.e
        c b(c cVar) {
            return cVar.f9403c;
        }

        @Override // k.b.e
        c c(c cVar) {
            return cVar.f9404d;
        }
    }

    static class c implements Map.Entry {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final Object f9401a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final Object f9402b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        c f9403c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        c f9404d;

        c(Object obj, Object obj2) {
            this.f9401a = obj;
            this.f9402b = obj2;
        }

        @Override // java.util.Map.Entry
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof c)) {
                return false;
            }
            c cVar = (c) obj;
            return this.f9401a.equals(cVar.f9401a) && this.f9402b.equals(cVar.f9402b);
        }

        @Override // java.util.Map.Entry
        public Object getKey() {
            return this.f9401a;
        }

        @Override // java.util.Map.Entry
        public Object getValue() {
            return this.f9402b;
        }

        @Override // java.util.Map.Entry
        public int hashCode() {
            return this.f9401a.hashCode() ^ this.f9402b.hashCode();
        }

        @Override // java.util.Map.Entry
        public Object setValue(Object obj) {
            throw new UnsupportedOperationException("An entry modification is not supported");
        }

        public String toString() {
            return this.f9401a + "=" + this.f9402b;
        }
    }

    public class d extends f implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private c f9405a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f9406b = true;

        d() {
        }

        @Override // k.b.f
        void a(c cVar) {
            c cVar2 = this.f9405a;
            if (cVar == cVar2) {
                c cVar3 = cVar2.f9404d;
                this.f9405a = cVar3;
                this.f9406b = cVar3 == null;
            }
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Map.Entry next() {
            if (this.f9406b) {
                this.f9406b = false;
                this.f9405a = b.this.f9397b;
            } else {
                c cVar = this.f9405a;
                this.f9405a = cVar != null ? cVar.f9403c : null;
            }
            return this.f9405a;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.f9406b) {
                return b.this.f9397b != null;
            }
            c cVar = this.f9405a;
            return (cVar == null || cVar.f9403c == null) ? false : true;
        }
    }

    private static abstract class e extends f implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        c f9408a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        c f9409b;

        e(c cVar, c cVar2) {
            this.f9408a = cVar2;
            this.f9409b = cVar;
        }

        private c e() {
            c cVar = this.f9409b;
            c cVar2 = this.f9408a;
            if (cVar == cVar2 || cVar2 == null) {
                return null;
            }
            return c(cVar);
        }

        @Override // k.b.f
        public void a(c cVar) {
            if (this.f9408a == cVar && cVar == this.f9409b) {
                this.f9409b = null;
                this.f9408a = null;
            }
            c cVar2 = this.f9408a;
            if (cVar2 == cVar) {
                this.f9408a = b(cVar2);
            }
            if (this.f9409b == cVar) {
                this.f9409b = e();
            }
        }

        abstract c b(c cVar);

        abstract c c(c cVar);

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
        public Map.Entry next() {
            c cVar = this.f9409b;
            this.f9409b = e();
            return cVar;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f9409b != null;
        }
    }

    public static abstract class f {
        abstract void a(c cVar);
    }

    public Iterator a() {
        C0136b c0136b = new C0136b(this.f9398c, this.f9397b);
        this.f9399d.put(c0136b, Boolean.FALSE);
        return c0136b;
    }

    public Map.Entry b() {
        return this.f9397b;
    }

    protected c c(Object obj) {
        c cVar = this.f9397b;
        while (cVar != null && !cVar.f9401a.equals(obj)) {
            cVar = cVar.f9403c;
        }
        return cVar;
    }

    public d e() {
        d dVar = new d();
        this.f9399d.put(dVar, Boolean.FALSE);
        return dVar;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        if (size() != bVar.size()) {
            return false;
        }
        Iterator it = iterator();
        Iterator it2 = bVar.iterator();
        while (it.hasNext() && it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Object next = it2.next();
            if ((entry == null && next != null) || (entry != null && !entry.equals(next))) {
                return false;
            }
        }
        return (it.hasNext() || it2.hasNext()) ? false : true;
    }

    public Map.Entry f() {
        return this.f9398c;
    }

    c h(Object obj, Object obj2) {
        c cVar = new c(obj, obj2);
        this.f9400e++;
        c cVar2 = this.f9398c;
        if (cVar2 == null) {
            this.f9397b = cVar;
            this.f9398c = cVar;
            return cVar;
        }
        cVar2.f9403c = cVar;
        cVar.f9404d = cVar2;
        this.f9398c = cVar;
        return cVar;
    }

    public int hashCode() {
        Iterator it = iterator();
        int iHashCode = 0;
        while (it.hasNext()) {
            iHashCode += ((Map.Entry) it.next()).hashCode();
        }
        return iHashCode;
    }

    public Object i(Object obj, Object obj2) {
        c cVarC = c(obj);
        if (cVarC != null) {
            return cVarC.f9402b;
        }
        h(obj, obj2);
        return null;
    }

    @Override // java.lang.Iterable
    public Iterator iterator() {
        a aVar = new a(this.f9397b, this.f9398c);
        this.f9399d.put(aVar, Boolean.FALSE);
        return aVar;
    }

    public Object j(Object obj) {
        c cVarC = c(obj);
        if (cVarC == null) {
            return null;
        }
        this.f9400e--;
        if (!this.f9399d.isEmpty()) {
            Iterator it = this.f9399d.keySet().iterator();
            while (it.hasNext()) {
                ((f) it.next()).a(cVarC);
            }
        }
        c cVar = cVarC.f9404d;
        if (cVar != null) {
            cVar.f9403c = cVarC.f9403c;
        } else {
            this.f9397b = cVarC.f9403c;
        }
        c cVar2 = cVarC.f9403c;
        if (cVar2 != null) {
            cVar2.f9404d = cVar;
        } else {
            this.f9398c = cVar;
        }
        cVarC.f9403c = null;
        cVarC.f9404d = null;
        return cVarC.f9402b;
    }

    public int size() {
        return this.f9400e;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        Iterator it = iterator();
        while (it.hasNext()) {
            sb.append(((Map.Entry) it.next()).toString());
            if (it.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append("]");
        return sb.toString();
    }
}
