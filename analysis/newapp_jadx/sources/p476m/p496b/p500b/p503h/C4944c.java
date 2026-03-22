package p476m.p496b.p500b.p503h;

/* renamed from: m.b.b.h.c */
/* loaded from: classes3.dex */
public final class C4944c<T> {

    /* renamed from: d */
    public int f12612d;

    /* renamed from: b */
    public int f12610b = 16;

    /* renamed from: c */
    public int f12611c = 21;

    /* renamed from: a */
    public a<T>[] f12609a = new a[16];

    /* renamed from: m.b.b.h.c$a */
    public static final class a<T> {

        /* renamed from: a */
        public final long f12613a;

        /* renamed from: b */
        public T f12614b;

        /* renamed from: c */
        public a<T> f12615c;

        public a(long j2, T t, a<T> aVar) {
            this.f12613a = j2;
            this.f12614b = t;
            this.f12615c = aVar;
        }
    }

    /* renamed from: a */
    public T m5612a(long j2) {
        for (a<T> aVar = this.f12609a[((((int) j2) ^ ((int) (j2 >>> 32))) & Integer.MAX_VALUE) % this.f12610b]; aVar != null; aVar = aVar.f12615c) {
            if (aVar.f12613a == j2) {
                return aVar.f12614b;
            }
        }
        return null;
    }

    /* renamed from: b */
    public T m5613b(long j2, T t) {
        int i2 = ((((int) j2) ^ ((int) (j2 >>> 32))) & Integer.MAX_VALUE) % this.f12610b;
        a<T> aVar = this.f12609a[i2];
        for (a<T> aVar2 = aVar; aVar2 != null; aVar2 = aVar2.f12615c) {
            if (aVar2.f12613a == j2) {
                T t2 = aVar2.f12614b;
                aVar2.f12614b = t;
                return t2;
            }
        }
        this.f12609a[i2] = new a<>(j2, t, aVar);
        int i3 = this.f12612d + 1;
        this.f12612d = i3;
        if (i3 <= this.f12611c) {
            return null;
        }
        m5614c(this.f12610b * 2);
        return null;
    }

    /* renamed from: c */
    public void m5614c(int i2) {
        a<T>[] aVarArr = new a[i2];
        int length = this.f12609a.length;
        for (int i3 = 0; i3 < length; i3++) {
            a<T> aVar = this.f12609a[i3];
            while (aVar != null) {
                long j2 = aVar.f12613a;
                int i4 = ((((int) (j2 >>> 32)) ^ ((int) j2)) & Integer.MAX_VALUE) % i2;
                a<T> aVar2 = aVar.f12615c;
                aVar.f12615c = aVarArr[i4];
                aVarArr[i4] = aVar;
                aVar = aVar2;
            }
        }
        this.f12609a = aVarArr;
        this.f12610b = i2;
        this.f12611c = (i2 * 4) / 3;
    }
}
