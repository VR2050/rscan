package l;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* JADX INFO: renamed from: l.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0607b implements Collection, Set {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final int[] f9426f = new int[0];

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final Object[] f9427g = new Object[0];

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static Object[] f9428h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static int f9429i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static Object[] f9430j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static int f9431k;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int[] f9432b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    Object[] f9433c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    int f9434d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private AbstractC0611f f9435e;

    /* JADX INFO: renamed from: l.b$a */
    class a extends AbstractC0611f {
        a() {
        }

        @Override // l.AbstractC0611f
        protected void a() {
            C0607b.this.clear();
        }

        @Override // l.AbstractC0611f
        protected Object b(int i3, int i4) {
            return C0607b.this.f9433c[i3];
        }

        @Override // l.AbstractC0611f
        protected Map c() {
            throw new UnsupportedOperationException("not a map");
        }

        @Override // l.AbstractC0611f
        protected int d() {
            return C0607b.this.f9434d;
        }

        @Override // l.AbstractC0611f
        protected int e(Object obj) {
            return C0607b.this.indexOf(obj);
        }

        @Override // l.AbstractC0611f
        protected int f(Object obj) {
            return C0607b.this.indexOf(obj);
        }

        @Override // l.AbstractC0611f
        protected void g(Object obj, Object obj2) {
            C0607b.this.add(obj);
        }

        @Override // l.AbstractC0611f
        protected void h(int i3) {
            C0607b.this.i(i3);
        }

        @Override // l.AbstractC0611f
        protected Object i(int i3, Object obj) {
            throw new UnsupportedOperationException("not a map");
        }
    }

    public C0607b() {
        this(0);
    }

    private void a(int i3) {
        if (i3 == 8) {
            synchronized (C0607b.class) {
                try {
                    Object[] objArr = f9430j;
                    if (objArr != null) {
                        this.f9433c = objArr;
                        f9430j = (Object[]) objArr[0];
                        this.f9432b = (int[]) objArr[1];
                        objArr[1] = null;
                        objArr[0] = null;
                        f9431k--;
                        return;
                    }
                } finally {
                }
            }
        } else if (i3 == 4) {
            synchronized (C0607b.class) {
                try {
                    Object[] objArr2 = f9428h;
                    if (objArr2 != null) {
                        this.f9433c = objArr2;
                        f9428h = (Object[]) objArr2[0];
                        this.f9432b = (int[]) objArr2[1];
                        objArr2[1] = null;
                        objArr2[0] = null;
                        f9429i--;
                        return;
                    }
                } finally {
                }
            }
        }
        this.f9432b = new int[i3];
        this.f9433c = new Object[i3];
    }

    private static void c(int[] iArr, Object[] objArr, int i3) {
        if (iArr.length == 8) {
            synchronized (C0607b.class) {
                try {
                    if (f9431k < 10) {
                        objArr[0] = f9430j;
                        objArr[1] = iArr;
                        for (int i4 = i3 - 1; i4 >= 2; i4--) {
                            objArr[i4] = null;
                        }
                        f9430j = objArr;
                        f9431k++;
                    }
                } finally {
                }
            }
            return;
        }
        if (iArr.length == 4) {
            synchronized (C0607b.class) {
                try {
                    if (f9429i < 10) {
                        objArr[0] = f9428h;
                        objArr[1] = iArr;
                        for (int i5 = i3 - 1; i5 >= 2; i5--) {
                            objArr[i5] = null;
                        }
                        f9428h = objArr;
                        f9429i++;
                    }
                } finally {
                }
            }
        }
    }

    private AbstractC0611f e() {
        if (this.f9435e == null) {
            this.f9435e = new a();
        }
        return this.f9435e;
    }

    private int f(Object obj, int i3) {
        int i4 = this.f9434d;
        if (i4 == 0) {
            return -1;
        }
        int iA = AbstractC0608c.a(this.f9432b, i4, i3);
        if (iA < 0 || obj.equals(this.f9433c[iA])) {
            return iA;
        }
        int i5 = iA + 1;
        while (i5 < i4 && this.f9432b[i5] == i3) {
            if (obj.equals(this.f9433c[i5])) {
                return i5;
            }
            i5++;
        }
        for (int i6 = iA - 1; i6 >= 0 && this.f9432b[i6] == i3; i6--) {
            if (obj.equals(this.f9433c[i6])) {
                return i6;
            }
        }
        return ~i5;
    }

    private int h() {
        int i3 = this.f9434d;
        if (i3 == 0) {
            return -1;
        }
        int iA = AbstractC0608c.a(this.f9432b, i3, 0);
        if (iA < 0 || this.f9433c[iA] == null) {
            return iA;
        }
        int i4 = iA + 1;
        while (i4 < i3 && this.f9432b[i4] == 0) {
            if (this.f9433c[i4] == null) {
                return i4;
            }
            i4++;
        }
        for (int i5 = iA - 1; i5 >= 0 && this.f9432b[i5] == 0; i5--) {
            if (this.f9433c[i5] == null) {
                return i5;
            }
        }
        return ~i4;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean add(Object obj) {
        int i3;
        int iF;
        if (obj == null) {
            iF = h();
            i3 = 0;
        } else {
            int iHashCode = obj.hashCode();
            i3 = iHashCode;
            iF = f(obj, iHashCode);
        }
        if (iF >= 0) {
            return false;
        }
        int i4 = ~iF;
        int i5 = this.f9434d;
        int[] iArr = this.f9432b;
        if (i5 >= iArr.length) {
            int i6 = 8;
            if (i5 >= 8) {
                i6 = (i5 >> 1) + i5;
            } else if (i5 < 4) {
                i6 = 4;
            }
            Object[] objArr = this.f9433c;
            a(i6);
            int[] iArr2 = this.f9432b;
            if (iArr2.length > 0) {
                System.arraycopy(iArr, 0, iArr2, 0, iArr.length);
                System.arraycopy(objArr, 0, this.f9433c, 0, objArr.length);
            }
            c(iArr, objArr, this.f9434d);
        }
        int i7 = this.f9434d;
        if (i4 < i7) {
            int[] iArr3 = this.f9432b;
            int i8 = i4 + 1;
            System.arraycopy(iArr3, i4, iArr3, i8, i7 - i4);
            Object[] objArr2 = this.f9433c;
            System.arraycopy(objArr2, i4, objArr2, i8, this.f9434d - i4);
        }
        this.f9432b[i4] = i3;
        this.f9433c[i4] = obj;
        this.f9434d++;
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean addAll(Collection collection) {
        b(this.f9434d + collection.size());
        Iterator it = collection.iterator();
        boolean zAdd = false;
        while (it.hasNext()) {
            zAdd |= add(it.next());
        }
        return zAdd;
    }

    public void b(int i3) {
        int[] iArr = this.f9432b;
        if (iArr.length < i3) {
            Object[] objArr = this.f9433c;
            a(i3);
            int i4 = this.f9434d;
            if (i4 > 0) {
                System.arraycopy(iArr, 0, this.f9432b, 0, i4);
                System.arraycopy(objArr, 0, this.f9433c, 0, this.f9434d);
            }
            c(iArr, objArr, this.f9434d);
        }
    }

    @Override // java.util.Collection, java.util.Set
    public void clear() {
        int i3 = this.f9434d;
        if (i3 != 0) {
            c(this.f9432b, this.f9433c, i3);
            this.f9432b = f9426f;
            this.f9433c = f9427g;
            this.f9434d = 0;
        }
    }

    @Override // java.util.Collection, java.util.Set
    public boolean contains(Object obj) {
        return indexOf(obj) >= 0;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean containsAll(Collection collection) {
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            if (!contains(it.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Set) {
            Set set = (Set) obj;
            if (size() != set.size()) {
                return false;
            }
            for (int i3 = 0; i3 < this.f9434d; i3++) {
                try {
                    if (!set.contains(j(i3))) {
                        return false;
                    }
                } catch (ClassCastException | NullPointerException unused) {
                }
            }
            return true;
        }
        return false;
    }

    @Override // java.util.Collection, java.util.Set
    public int hashCode() {
        int[] iArr = this.f9432b;
        int i3 = this.f9434d;
        int i4 = 0;
        for (int i5 = 0; i5 < i3; i5++) {
            i4 += iArr[i5];
        }
        return i4;
    }

    public Object i(int i3) {
        Object[] objArr = this.f9433c;
        Object obj = objArr[i3];
        int i4 = this.f9434d;
        if (i4 <= 1) {
            c(this.f9432b, objArr, i4);
            this.f9432b = f9426f;
            this.f9433c = f9427g;
            this.f9434d = 0;
        } else {
            int[] iArr = this.f9432b;
            if (iArr.length <= 8 || i4 >= iArr.length / 3) {
                int i5 = i4 - 1;
                this.f9434d = i5;
                if (i3 < i5) {
                    int i6 = i3 + 1;
                    System.arraycopy(iArr, i6, iArr, i3, i5 - i3);
                    Object[] objArr2 = this.f9433c;
                    System.arraycopy(objArr2, i6, objArr2, i3, this.f9434d - i3);
                }
                this.f9433c[this.f9434d] = null;
            } else {
                a(i4 > 8 ? i4 + (i4 >> 1) : 8);
                this.f9434d--;
                if (i3 > 0) {
                    System.arraycopy(iArr, 0, this.f9432b, 0, i3);
                    System.arraycopy(objArr, 0, this.f9433c, 0, i3);
                }
                int i7 = this.f9434d;
                if (i3 < i7) {
                    int i8 = i3 + 1;
                    System.arraycopy(iArr, i8, this.f9432b, i3, i7 - i3);
                    System.arraycopy(objArr, i8, this.f9433c, i3, this.f9434d - i3);
                }
            }
        }
        return obj;
    }

    public int indexOf(Object obj) {
        return obj == null ? h() : f(obj, obj.hashCode());
    }

    @Override // java.util.Collection, java.util.Set
    public boolean isEmpty() {
        return this.f9434d <= 0;
    }

    @Override // java.util.Collection, java.lang.Iterable, java.util.Set
    public Iterator iterator() {
        return e().m().iterator();
    }

    public Object j(int i3) {
        return this.f9433c[i3];
    }

    @Override // java.util.Collection, java.util.Set
    public boolean remove(Object obj) {
        int iIndexOf = indexOf(obj);
        if (iIndexOf < 0) {
            return false;
        }
        i(iIndexOf);
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean removeAll(Collection collection) {
        Iterator it = collection.iterator();
        boolean zRemove = false;
        while (it.hasNext()) {
            zRemove |= remove(it.next());
        }
        return zRemove;
    }

    @Override // java.util.Collection, java.util.Set
    public boolean retainAll(Collection collection) {
        boolean z3 = false;
        for (int i3 = this.f9434d - 1; i3 >= 0; i3--) {
            if (!collection.contains(this.f9433c[i3])) {
                i(i3);
                z3 = true;
            }
        }
        return z3;
    }

    @Override // java.util.Collection, java.util.Set
    public int size() {
        return this.f9434d;
    }

    @Override // java.util.Collection, java.util.Set
    public Object[] toArray() {
        int i3 = this.f9434d;
        Object[] objArr = new Object[i3];
        System.arraycopy(this.f9433c, 0, objArr, 0, i3);
        return objArr;
    }

    public String toString() {
        if (isEmpty()) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder(this.f9434d * 14);
        sb.append('{');
        for (int i3 = 0; i3 < this.f9434d; i3++) {
            if (i3 > 0) {
                sb.append(", ");
            }
            Object objJ = j(i3);
            if (objJ != this) {
                sb.append(objJ);
            } else {
                sb.append("(this Set)");
            }
        }
        sb.append('}');
        return sb.toString();
    }

    public C0607b(int i3) {
        if (i3 == 0) {
            this.f9432b = f9426f;
            this.f9433c = f9427g;
        } else {
            a(i3);
        }
        this.f9434d = 0;
    }

    @Override // java.util.Collection, java.util.Set
    public Object[] toArray(Object[] objArr) {
        if (objArr.length < this.f9434d) {
            objArr = (Object[]) Array.newInstance(objArr.getClass().getComponentType(), this.f9434d);
        }
        System.arraycopy(this.f9433c, 0, objArr, 0, this.f9434d);
        int length = objArr.length;
        int i3 = this.f9434d;
        if (length > i3) {
            objArr[i3] = null;
        }
        return objArr;
    }
}
