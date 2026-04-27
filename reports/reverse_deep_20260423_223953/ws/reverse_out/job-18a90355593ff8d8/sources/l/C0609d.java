package l;

/* JADX INFO: renamed from: l.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0609d implements Cloneable {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Object f9440f = new Object();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f9441b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long[] f9442c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Object[] f9443d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f9444e;

    public C0609d() {
        this(10);
    }

    private void d() {
        int i3 = this.f9444e;
        long[] jArr = this.f9442c;
        Object[] objArr = this.f9443d;
        int i4 = 0;
        for (int i5 = 0; i5 < i3; i5++) {
            Object obj = objArr[i5];
            if (obj != f9440f) {
                if (i5 != i4) {
                    jArr[i4] = jArr[i5];
                    objArr[i4] = obj;
                    objArr[i5] = null;
                }
                i4++;
            }
        }
        this.f9441b = false;
        this.f9444e = i4;
    }

    public void a() {
        int i3 = this.f9444e;
        Object[] objArr = this.f9443d;
        for (int i4 = 0; i4 < i3; i4++) {
            objArr[i4] = null;
        }
        this.f9444e = 0;
        this.f9441b = false;
    }

    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public C0609d clone() {
        try {
            C0609d c0609d = (C0609d) super.clone();
            c0609d.f9442c = (long[]) this.f9442c.clone();
            c0609d.f9443d = (Object[]) this.f9443d.clone();
            return c0609d;
        } catch (CloneNotSupportedException e3) {
            throw new AssertionError(e3);
        }
    }

    public Object e(long j3) {
        return f(j3, null);
    }

    public Object f(long j3, Object obj) {
        Object obj2;
        int iB = AbstractC0608c.b(this.f9442c, this.f9444e, j3);
        return (iB < 0 || (obj2 = this.f9443d[iB]) == f9440f) ? obj : obj2;
    }

    public long g(int i3) {
        if (this.f9441b) {
            d();
        }
        return this.f9442c[i3];
    }

    public void h(long j3, Object obj) {
        int iB = AbstractC0608c.b(this.f9442c, this.f9444e, j3);
        if (iB >= 0) {
            this.f9443d[iB] = obj;
            return;
        }
        int i3 = ~iB;
        int i4 = this.f9444e;
        if (i3 < i4) {
            Object[] objArr = this.f9443d;
            if (objArr[i3] == f9440f) {
                this.f9442c[i3] = j3;
                objArr[i3] = obj;
                return;
            }
        }
        if (this.f9441b && i4 >= this.f9442c.length) {
            d();
            i3 = ~AbstractC0608c.b(this.f9442c, this.f9444e, j3);
        }
        int i5 = this.f9444e;
        if (i5 >= this.f9442c.length) {
            int iF = AbstractC0608c.f(i5 + 1);
            long[] jArr = new long[iF];
            Object[] objArr2 = new Object[iF];
            long[] jArr2 = this.f9442c;
            System.arraycopy(jArr2, 0, jArr, 0, jArr2.length);
            Object[] objArr3 = this.f9443d;
            System.arraycopy(objArr3, 0, objArr2, 0, objArr3.length);
            this.f9442c = jArr;
            this.f9443d = objArr2;
        }
        int i6 = this.f9444e;
        if (i6 - i3 != 0) {
            long[] jArr3 = this.f9442c;
            int i7 = i3 + 1;
            System.arraycopy(jArr3, i3, jArr3, i7, i6 - i3);
            Object[] objArr4 = this.f9443d;
            System.arraycopy(objArr4, i3, objArr4, i7, this.f9444e - i3);
        }
        this.f9442c[i3] = j3;
        this.f9443d[i3] = obj;
        this.f9444e++;
    }

    public void j(long j3) {
        int iB = AbstractC0608c.b(this.f9442c, this.f9444e, j3);
        if (iB >= 0) {
            Object[] objArr = this.f9443d;
            Object obj = objArr[iB];
            Object obj2 = f9440f;
            if (obj != obj2) {
                objArr[iB] = obj2;
                this.f9441b = true;
            }
        }
    }

    public int k() {
        if (this.f9441b) {
            d();
        }
        return this.f9444e;
    }

    public Object l(int i3) {
        if (this.f9441b) {
            d();
        }
        return this.f9443d[i3];
    }

    public String toString() {
        if (k() <= 0) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder(this.f9444e * 28);
        sb.append('{');
        for (int i3 = 0; i3 < this.f9444e; i3++) {
            if (i3 > 0) {
                sb.append(", ");
            }
            sb.append(g(i3));
            sb.append('=');
            Object objL = l(i3);
            if (objL != this) {
                sb.append(objL);
            } else {
                sb.append("(this Map)");
            }
        }
        sb.append('}');
        return sb.toString();
    }

    public C0609d(int i3) {
        this.f9441b = false;
        if (i3 == 0) {
            this.f9442c = AbstractC0608c.f9438b;
            this.f9443d = AbstractC0608c.f9439c;
        } else {
            int iF = AbstractC0608c.f(i3);
            this.f9442c = new long[iF];
            this.f9443d = new Object[iF];
        }
    }
}
