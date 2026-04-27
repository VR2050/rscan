package j2;

import i2.AbstractC0574b;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: renamed from: j2.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0598c implements Map, Serializable {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final a f9372o = new a(null);

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final C0598c f9373p;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Object[] f9374b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Object[] f9375c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int[] f9376d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int[] f9377e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f9378f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f9379g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f9380h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f9381i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f9382j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private C0600e f9383k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private C0601f f9384l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private C0599d f9385m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f9386n;

    /* JADX INFO: renamed from: j2.c$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final int c(int i3) {
            return Integer.highestOneBit(w2.d.c(i3, 1) * 3);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final int d(int i3) {
            return Integer.numberOfLeadingZeros(i3) + 1;
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: j2.c$b */
    public static final class b extends d implements Iterator {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(C0598c c0598c) {
            super(c0598c);
            j.f(c0598c, "map");
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
        public C0135c next() {
            a();
            if (b() >= d().f9379g) {
                throw new NoSuchElementException();
            }
            int iB = b();
            f(iB + 1);
            g(iB);
            C0135c c0135c = new C0135c(d(), c());
            e();
            return c0135c;
        }

        public final void i(StringBuilder sb) {
            j.f(sb, "sb");
            if (b() >= d().f9379g) {
                throw new NoSuchElementException();
            }
            int iB = b();
            f(iB + 1);
            g(iB);
            Object obj = d().f9374b[c()];
            if (obj == d()) {
                sb.append("(this Map)");
            } else {
                sb.append(obj);
            }
            sb.append('=');
            Object[] objArr = d().f9375c;
            j.c(objArr);
            Object obj2 = objArr[c()];
            if (obj2 == d()) {
                sb.append("(this Map)");
            } else {
                sb.append(obj2);
            }
            e();
        }

        public final int j() {
            if (b() >= d().f9379g) {
                throw new NoSuchElementException();
            }
            int iB = b();
            f(iB + 1);
            g(iB);
            Object obj = d().f9374b[c()];
            int iHashCode = obj != null ? obj.hashCode() : 0;
            Object[] objArr = d().f9375c;
            j.c(objArr);
            Object obj2 = objArr[c()];
            int iHashCode2 = iHashCode ^ (obj2 != null ? obj2.hashCode() : 0);
            e();
            return iHashCode2;
        }
    }

    /* JADX INFO: renamed from: j2.c$c, reason: collision with other inner class name */
    public static final class C0135c implements Map.Entry {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0598c f9387a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f9388b;

        public C0135c(C0598c c0598c, int i3) {
            j.f(c0598c, "map");
            this.f9387a = c0598c;
            this.f9388b = i3;
        }

        @Override // java.util.Map.Entry
        public boolean equals(Object obj) {
            if (obj instanceof Map.Entry) {
                Map.Entry entry = (Map.Entry) obj;
                if (j.b(entry.getKey(), getKey()) && j.b(entry.getValue(), getValue())) {
                    return true;
                }
            }
            return false;
        }

        @Override // java.util.Map.Entry
        public Object getKey() {
            return this.f9387a.f9374b[this.f9388b];
        }

        @Override // java.util.Map.Entry
        public Object getValue() {
            Object[] objArr = this.f9387a.f9375c;
            j.c(objArr);
            return objArr[this.f9388b];
        }

        @Override // java.util.Map.Entry
        public int hashCode() {
            Object key = getKey();
            int iHashCode = key != null ? key.hashCode() : 0;
            Object value = getValue();
            return iHashCode ^ (value != null ? value.hashCode() : 0);
        }

        @Override // java.util.Map.Entry
        public Object setValue(Object obj) {
            this.f9387a.k();
            Object[] objArrI = this.f9387a.i();
            int i3 = this.f9388b;
            Object obj2 = objArrI[i3];
            objArrI[i3] = obj;
            return obj2;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(getKey());
            sb.append('=');
            sb.append(getValue());
            return sb.toString();
        }
    }

    /* JADX INFO: renamed from: j2.c$d */
    public static class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final C0598c f9389a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f9390b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f9391c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f9392d;

        public d(C0598c c0598c) {
            j.f(c0598c, "map");
            this.f9389a = c0598c;
            this.f9391c = -1;
            this.f9392d = c0598c.f9381i;
            e();
        }

        public final void a() {
            if (this.f9389a.f9381i != this.f9392d) {
                throw new ConcurrentModificationException();
            }
        }

        public final int b() {
            return this.f9390b;
        }

        public final int c() {
            return this.f9391c;
        }

        public final C0598c d() {
            return this.f9389a;
        }

        public final void e() {
            while (this.f9390b < this.f9389a.f9379g) {
                int[] iArr = this.f9389a.f9376d;
                int i3 = this.f9390b;
                if (iArr[i3] >= 0) {
                    return;
                } else {
                    this.f9390b = i3 + 1;
                }
            }
        }

        public final void f(int i3) {
            this.f9390b = i3;
        }

        public final void g(int i3) {
            this.f9391c = i3;
        }

        public final boolean hasNext() {
            return this.f9390b < this.f9389a.f9379g;
        }

        public final void remove() {
            a();
            if (this.f9391c == -1) {
                throw new IllegalStateException("Call next() before removing element from the iterator.");
            }
            this.f9389a.k();
            this.f9389a.I(this.f9391c);
            this.f9391c = -1;
            this.f9392d = this.f9389a.f9381i;
        }
    }

    /* JADX INFO: renamed from: j2.c$e */
    public static final class e extends d implements Iterator {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public e(C0598c c0598c) {
            super(c0598c);
            j.f(c0598c, "map");
        }

        @Override // java.util.Iterator
        public Object next() {
            a();
            if (b() >= d().f9379g) {
                throw new NoSuchElementException();
            }
            int iB = b();
            f(iB + 1);
            g(iB);
            Object obj = d().f9374b[c()];
            e();
            return obj;
        }
    }

    /* JADX INFO: renamed from: j2.c$f */
    public static final class f extends d implements Iterator {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public f(C0598c c0598c) {
            super(c0598c);
            j.f(c0598c, "map");
        }

        @Override // java.util.Iterator
        public Object next() {
            a();
            if (b() >= d().f9379g) {
                throw new NoSuchElementException();
            }
            int iB = b();
            f(iB + 1);
            g(iB);
            Object[] objArr = d().f9375c;
            j.c(objArr);
            Object obj = objArr[c()];
            e();
            return obj;
        }
    }

    static {
        C0598c c0598c = new C0598c(0);
        c0598c.f9386n = true;
        f9373p = c0598c;
    }

    private C0598c(Object[] objArr, Object[] objArr2, int[] iArr, int[] iArr2, int i3, int i4) {
        this.f9374b = objArr;
        this.f9375c = objArr2;
        this.f9376d = iArr;
        this.f9377e = iArr2;
        this.f9378f = i3;
        this.f9379g = i4;
        this.f9380h = f9372o.d(w());
    }

    private final int A(Object obj) {
        return ((obj != null ? obj.hashCode() : 0) * (-1640531527)) >>> this.f9380h;
    }

    private final boolean C(Collection collection) {
        boolean z3 = false;
        if (collection.isEmpty()) {
            return false;
        }
        q(collection.size());
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            if (D((Map.Entry) it.next())) {
                z3 = true;
            }
        }
        return z3;
    }

    private final boolean D(Map.Entry entry) {
        int iH = h(entry.getKey());
        Object[] objArrI = i();
        if (iH >= 0) {
            objArrI[iH] = entry.getValue();
            return true;
        }
        int i3 = (-iH) - 1;
        if (j.b(entry.getValue(), objArrI[i3])) {
            return false;
        }
        objArrI[i3] = entry.getValue();
        return true;
    }

    private final boolean E(int i3) {
        int iA = A(this.f9374b[i3]);
        int i4 = this.f9378f;
        while (true) {
            int[] iArr = this.f9377e;
            if (iArr[iA] == 0) {
                iArr[iA] = i3 + 1;
                this.f9376d[i3] = iA;
                return true;
            }
            i4--;
            if (i4 < 0) {
                return false;
            }
            iA = iA == 0 ? w() - 1 : iA - 1;
        }
    }

    private final void F() {
        this.f9381i++;
    }

    private final void G(int i3) {
        F();
        int i4 = 0;
        if (this.f9379g > size()) {
            l(false);
        }
        this.f9377e = new int[i3];
        this.f9380h = f9372o.d(i3);
        while (i4 < this.f9379g) {
            int i5 = i4 + 1;
            if (!E(i4)) {
                throw new IllegalStateException("This cannot happen with fixed magic multiplier and grow-only hash array. Have object hashCodes changed?");
            }
            i4 = i5;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void I(int i3) {
        AbstractC0597b.c(this.f9374b, i3);
        Object[] objArr = this.f9375c;
        if (objArr != null) {
            AbstractC0597b.c(objArr, i3);
        }
        J(this.f9376d[i3]);
        this.f9376d[i3] = -1;
        this.f9382j = size() - 1;
        F();
    }

    private final void J(int i3) {
        int iE = w2.d.e(this.f9378f * 2, w() / 2);
        int i4 = 0;
        int i5 = i3;
        do {
            i3 = i3 == 0 ? w() - 1 : i3 - 1;
            i4++;
            if (i4 > this.f9378f) {
                this.f9377e[i5] = 0;
                return;
            }
            int[] iArr = this.f9377e;
            int i6 = iArr[i3];
            if (i6 == 0) {
                iArr[i5] = 0;
                return;
            }
            if (i6 < 0) {
                iArr[i5] = -1;
            } else {
                int i7 = i6 - 1;
                if (((A(this.f9374b[i7]) - i3) & (w() - 1)) >= i4) {
                    this.f9377e[i5] = i6;
                    this.f9376d[i7] = i5;
                }
                iE--;
            }
            i5 = i3;
            i4 = 0;
            iE--;
        } while (iE >= 0);
        this.f9377e[i5] = -1;
    }

    private final boolean M(int i3) {
        int iU = u();
        int i4 = this.f9379g;
        int i5 = iU - i4;
        int size = i4 - size();
        return i5 < i3 && i5 + size >= i3 && size >= u() / 4;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Object[] i() {
        Object[] objArr = this.f9375c;
        if (objArr != null) {
            return objArr;
        }
        Object[] objArrA = AbstractC0597b.a(u());
        this.f9375c = objArrA;
        return objArrA;
    }

    private final void l(boolean z3) {
        int i3;
        Object[] objArr = this.f9375c;
        int i4 = 0;
        int i5 = 0;
        while (true) {
            i3 = this.f9379g;
            if (i4 >= i3) {
                break;
            }
            int[] iArr = this.f9376d;
            int i6 = iArr[i4];
            if (i6 >= 0) {
                Object[] objArr2 = this.f9374b;
                objArr2[i5] = objArr2[i4];
                if (objArr != null) {
                    objArr[i5] = objArr[i4];
                }
                if (z3) {
                    iArr[i5] = i6;
                    this.f9377e[i6] = i5 + 1;
                }
                i5++;
            }
            i4++;
        }
        AbstractC0597b.d(this.f9374b, i5, i3);
        if (objArr != null) {
            AbstractC0597b.d(objArr, i5, this.f9379g);
        }
        this.f9379g = i5;
    }

    private final boolean o(Map map) {
        return size() == map.size() && m(map.entrySet());
    }

    private final void p(int i3) {
        if (i3 < 0) {
            throw new OutOfMemoryError();
        }
        if (i3 > u()) {
            int iD = AbstractC0574b.f9337b.d(u(), i3);
            this.f9374b = AbstractC0597b.b(this.f9374b, iD);
            Object[] objArr = this.f9375c;
            this.f9375c = objArr != null ? AbstractC0597b.b(objArr, iD) : null;
            int[] iArrCopyOf = Arrays.copyOf(this.f9376d, iD);
            j.e(iArrCopyOf, "copyOf(...)");
            this.f9376d = iArrCopyOf;
            int iC = f9372o.c(iD);
            if (iC > w()) {
                G(iC);
            }
        }
    }

    private final void q(int i3) {
        if (M(i3)) {
            l(true);
        } else {
            p(this.f9379g + i3);
        }
    }

    private final int s(Object obj) {
        int iA = A(obj);
        int i3 = this.f9378f;
        while (true) {
            int i4 = this.f9377e[iA];
            if (i4 == 0) {
                return -1;
            }
            if (i4 > 0) {
                int i5 = i4 - 1;
                if (j.b(this.f9374b[i5], obj)) {
                    return i5;
                }
            }
            i3--;
            if (i3 < 0) {
                return -1;
            }
            iA = iA == 0 ? w() - 1 : iA - 1;
        }
    }

    private final int t(Object obj) {
        int i3 = this.f9379g;
        while (true) {
            i3--;
            if (i3 < 0) {
                return -1;
            }
            if (this.f9376d[i3] >= 0) {
                Object[] objArr = this.f9375c;
                j.c(objArr);
                if (j.b(objArr[i3], obj)) {
                    return i3;
                }
            }
        }
    }

    private final int w() {
        return this.f9377e.length;
    }

    public final e B() {
        return new e(this);
    }

    public final boolean H(Map.Entry entry) {
        j.f(entry, "entry");
        k();
        int iS = s(entry.getKey());
        if (iS < 0) {
            return false;
        }
        Object[] objArr = this.f9375c;
        j.c(objArr);
        if (!j.b(objArr[iS], entry.getValue())) {
            return false;
        }
        I(iS);
        return true;
    }

    public final boolean K(Object obj) {
        k();
        int iS = s(obj);
        if (iS < 0) {
            return false;
        }
        I(iS);
        return true;
    }

    public final boolean L(Object obj) {
        k();
        int iT = t(obj);
        if (iT < 0) {
            return false;
        }
        I(iT);
        return true;
    }

    public final f N() {
        return new f(this);
    }

    @Override // java.util.Map
    public void clear() {
        k();
        int i3 = this.f9379g - 1;
        if (i3 >= 0) {
            int i4 = 0;
            while (true) {
                int[] iArr = this.f9376d;
                int i5 = iArr[i4];
                if (i5 >= 0) {
                    this.f9377e[i5] = 0;
                    iArr[i4] = -1;
                }
                if (i4 == i3) {
                    break;
                } else {
                    i4++;
                }
            }
        }
        AbstractC0597b.d(this.f9374b, 0, this.f9379g);
        Object[] objArr = this.f9375c;
        if (objArr != null) {
            AbstractC0597b.d(objArr, 0, this.f9379g);
        }
        this.f9382j = 0;
        this.f9379g = 0;
        F();
    }

    @Override // java.util.Map
    public boolean containsKey(Object obj) {
        return s(obj) >= 0;
    }

    @Override // java.util.Map
    public boolean containsValue(Object obj) {
        return t(obj) >= 0;
    }

    @Override // java.util.Map
    public final /* bridge */ Set entrySet() {
        return v();
    }

    @Override // java.util.Map
    public boolean equals(Object obj) {
        return obj == this || ((obj instanceof Map) && o((Map) obj));
    }

    @Override // java.util.Map
    public Object get(Object obj) {
        int iS = s(obj);
        if (iS < 0) {
            return null;
        }
        Object[] objArr = this.f9375c;
        j.c(objArr);
        return objArr[iS];
    }

    public final int h(Object obj) {
        k();
        while (true) {
            int iA = A(obj);
            int iE = w2.d.e(this.f9378f * 2, w() / 2);
            int i3 = 0;
            while (true) {
                int i4 = this.f9377e[iA];
                if (i4 <= 0) {
                    if (this.f9379g < u()) {
                        int i5 = this.f9379g;
                        int i6 = i5 + 1;
                        this.f9379g = i6;
                        this.f9374b[i5] = obj;
                        this.f9376d[i5] = iA;
                        this.f9377e[iA] = i6;
                        this.f9382j = size() + 1;
                        F();
                        if (i3 > this.f9378f) {
                            this.f9378f = i3;
                        }
                        return i5;
                    }
                    q(1);
                } else {
                    if (j.b(this.f9374b[i4 - 1], obj)) {
                        return -i4;
                    }
                    i3++;
                    if (i3 > iE) {
                        G(w() * 2);
                        break;
                    }
                    iA = iA == 0 ? w() - 1 : iA - 1;
                }
            }
        }
    }

    @Override // java.util.Map
    public int hashCode() {
        b bVarR = r();
        int iJ = 0;
        while (bVarR.hasNext()) {
            iJ += bVarR.j();
        }
        return iJ;
    }

    @Override // java.util.Map
    public boolean isEmpty() {
        return size() == 0;
    }

    public final Map j() {
        k();
        this.f9386n = true;
        if (size() > 0) {
            return this;
        }
        C0598c c0598c = f9373p;
        j.d(c0598c, "null cannot be cast to non-null type kotlin.collections.Map<K of kotlin.collections.builders.MapBuilder, V of kotlin.collections.builders.MapBuilder>");
        return c0598c;
    }

    public final void k() {
        if (this.f9386n) {
            throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.Map
    public final /* bridge */ Set keySet() {
        return x();
    }

    public final boolean m(Collection collection) {
        j.f(collection, "m");
        for (Object obj : collection) {
            if (obj != null) {
                try {
                    if (!n((Map.Entry) obj)) {
                    }
                } catch (ClassCastException unused) {
                }
            }
            return false;
        }
        return true;
    }

    public final boolean n(Map.Entry entry) {
        j.f(entry, "entry");
        int iS = s(entry.getKey());
        if (iS < 0) {
            return false;
        }
        Object[] objArr = this.f9375c;
        j.c(objArr);
        return j.b(objArr[iS], entry.getValue());
    }

    @Override // java.util.Map
    public Object put(Object obj, Object obj2) {
        k();
        int iH = h(obj);
        Object[] objArrI = i();
        if (iH >= 0) {
            objArrI[iH] = obj2;
            return null;
        }
        int i3 = (-iH) - 1;
        Object obj3 = objArrI[i3];
        objArrI[i3] = obj2;
        return obj3;
    }

    @Override // java.util.Map
    public void putAll(Map map) {
        j.f(map, "from");
        k();
        C(map.entrySet());
    }

    public final b r() {
        return new b(this);
    }

    @Override // java.util.Map
    public Object remove(Object obj) {
        k();
        int iS = s(obj);
        if (iS < 0) {
            return null;
        }
        Object[] objArr = this.f9375c;
        j.c(objArr);
        Object obj2 = objArr[iS];
        I(iS);
        return obj2;
    }

    @Override // java.util.Map
    public final /* bridge */ int size() {
        return y();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder((size() * 3) + 2);
        sb.append("{");
        b bVarR = r();
        int i3 = 0;
        while (bVarR.hasNext()) {
            if (i3 > 0) {
                sb.append(", ");
            }
            bVarR.i(sb);
            i3++;
        }
        sb.append("}");
        String string = sb.toString();
        j.e(string, "toString(...)");
        return string;
    }

    public final int u() {
        return this.f9374b.length;
    }

    public Set v() {
        C0599d c0599d = this.f9385m;
        if (c0599d != null) {
            return c0599d;
        }
        C0599d c0599d2 = new C0599d(this);
        this.f9385m = c0599d2;
        return c0599d2;
    }

    @Override // java.util.Map
    public final /* bridge */ Collection values() {
        return z();
    }

    public Set x() {
        C0600e c0600e = this.f9383k;
        if (c0600e != null) {
            return c0600e;
        }
        C0600e c0600e2 = new C0600e(this);
        this.f9383k = c0600e2;
        return c0600e2;
    }

    public int y() {
        return this.f9382j;
    }

    public Collection z() {
        C0601f c0601f = this.f9384l;
        if (c0601f != null) {
            return c0601f;
        }
        C0601f c0601f2 = new C0601f(this);
        this.f9384l = c0601f2;
        return c0601f2;
    }

    public C0598c() {
        this(8);
    }

    public C0598c(int i3) {
        this(AbstractC0597b.a(i3), null, new int[i3], new int[f9372o.c(i3)], 2, 0);
    }
}
