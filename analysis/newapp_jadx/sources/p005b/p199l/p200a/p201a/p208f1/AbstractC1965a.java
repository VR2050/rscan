package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.a */
/* loaded from: classes.dex */
public abstract class AbstractC1965a {

    /* renamed from: a */
    public final a f3395a;

    /* renamed from: b */
    public final f f3396b;

    /* renamed from: c */
    @Nullable
    public c f3397c;

    /* renamed from: d */
    public final int f3398d;

    /* renamed from: b.l.a.a.f1.a$a */
    public static class a implements InterfaceC2050q {

        /* renamed from: a */
        public final d f3399a;

        /* renamed from: b */
        public final long f3400b;

        /* renamed from: c */
        public final long f3401c;

        /* renamed from: d */
        public final long f3402d;

        /* renamed from: e */
        public final long f3403e;

        /* renamed from: f */
        public final long f3404f;

        /* renamed from: g */
        public final long f3405g;

        public a(d dVar, long j2, long j3, long j4, long j5, long j6, long j7) {
            this.f3399a = dVar;
            this.f3400b = j2;
            this.f3401c = j3;
            this.f3402d = j4;
            this.f3403e = j5;
            this.f3404f = j6;
            this.f3405g = j7;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: c */
        public boolean mo1462c() {
            return true;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: g */
        public InterfaceC2050q.a mo1463g(long j2) {
            return new InterfaceC2050q.a(new C2051r(j2, c.m1466a(this.f3399a.mo1465a(j2), this.f3401c, this.f3402d, this.f3403e, this.f3404f, this.f3405g)));
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
        /* renamed from: i */
        public long mo1464i() {
            return this.f3400b;
        }
    }

    /* renamed from: b.l.a.a.f1.a$b */
    public static final class b implements d {
        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.d
        /* renamed from: a */
        public long mo1465a(long j2) {
            return j2;
        }
    }

    /* renamed from: b.l.a.a.f1.a$c */
    public static class c {

        /* renamed from: a */
        public final long f3406a;

        /* renamed from: b */
        public final long f3407b;

        /* renamed from: c */
        public final long f3408c;

        /* renamed from: d */
        public long f3409d;

        /* renamed from: e */
        public long f3410e;

        /* renamed from: f */
        public long f3411f;

        /* renamed from: g */
        public long f3412g;

        /* renamed from: h */
        public long f3413h;

        public c(long j2, long j3, long j4, long j5, long j6, long j7, long j8) {
            this.f3406a = j2;
            this.f3407b = j3;
            this.f3409d = j4;
            this.f3410e = j5;
            this.f3411f = j6;
            this.f3412g = j7;
            this.f3408c = j8;
            this.f3413h = m1466a(j3, j4, j5, j6, j7, j8);
        }

        /* renamed from: a */
        public static long m1466a(long j2, long j3, long j4, long j5, long j6, long j7) {
            if (j5 + 1 >= j6 || j3 + 1 >= j4) {
                return j5;
            }
            long j8 = (long) ((j2 - j3) * ((j6 - j5) / (j4 - j3)));
            return C2344d0.m2330h(((j8 + j5) - j7) - (j8 / 20), j5, j6 - 1);
        }
    }

    /* renamed from: b.l.a.a.f1.a$d */
    public interface d {
        /* renamed from: a */
        long mo1465a(long j2);
    }

    /* renamed from: b.l.a.a.f1.a$e */
    public static final class e {

        /* renamed from: a */
        public static final e f3414a = new e(-3, -9223372036854775807L, -1);

        /* renamed from: b */
        public final int f3415b;

        /* renamed from: c */
        public final long f3416c;

        /* renamed from: d */
        public final long f3417d;

        public e(int i2, long j2, long j3) {
            this.f3415b = i2;
            this.f3416c = j2;
            this.f3417d = j3;
        }

        /* renamed from: a */
        public static e m1467a(long j2, long j3) {
            return new e(-1, j2, j3);
        }

        /* renamed from: b */
        public static e m1468b(long j2) {
            return new e(0, -9223372036854775807L, j2);
        }

        /* renamed from: c */
        public static e m1469c(long j2, long j3) {
            return new e(-2, j2, j3);
        }
    }

    /* renamed from: b.l.a.a.f1.a$f */
    public interface f {
        /* renamed from: a */
        e mo1470a(C2003e c2003e, long j2);

        /* renamed from: b */
        void mo1471b();
    }

    public AbstractC1965a(d dVar, f fVar, long j2, long j3, long j4, long j5, long j6, long j7, int i2) {
        this.f3396b = fVar;
        this.f3398d = i2;
        this.f3395a = new a(dVar, j2, j3, j4, j5, j6, j7);
    }

    /* renamed from: a */
    public int m1456a(C2003e c2003e, C2049p c2049p) {
        C2003e c2003e2 = c2003e;
        C2049p c2049p2 = c2049p;
        f fVar = this.f3396b;
        Objects.requireNonNull(fVar);
        while (true) {
            c cVar = this.f3397c;
            Objects.requireNonNull(cVar);
            long j2 = cVar.f3411f;
            long j3 = cVar.f3412g;
            long j4 = cVar.f3413h;
            if (j3 - j2 <= this.f3398d) {
                m1458c(false, j2);
                return m1459d(c2003e2, j2, c2049p2);
            }
            if (!m1461f(c2003e2, j4)) {
                return m1459d(c2003e2, j4, c2049p2);
            }
            c2003e2.f3791f = 0;
            e mo1470a = fVar.mo1470a(c2003e2, cVar.f3407b);
            int i2 = mo1470a.f3415b;
            if (i2 == -3) {
                m1458c(false, j4);
                return m1459d(c2003e, j4, c2049p);
            }
            if (i2 == -2) {
                long j5 = mo1470a.f3416c;
                long j6 = mo1470a.f3417d;
                cVar.f3409d = j5;
                cVar.f3411f = j6;
                cVar.f3413h = c.m1466a(cVar.f3407b, j5, cVar.f3410e, j6, cVar.f3412g, cVar.f3408c);
            } else {
                if (i2 != -1) {
                    if (i2 != 0) {
                        throw new IllegalStateException("Invalid case");
                    }
                    m1458c(true, mo1470a.f3417d);
                    m1461f(c2003e2, mo1470a.f3417d);
                    return m1459d(c2003e2, mo1470a.f3417d, c2049p2);
                }
                long j7 = mo1470a.f3416c;
                long j8 = mo1470a.f3417d;
                cVar.f3410e = j7;
                cVar.f3412g = j8;
                cVar.f3413h = c.m1466a(cVar.f3407b, cVar.f3409d, j7, cVar.f3411f, j8, cVar.f3408c);
            }
            c2003e2 = c2003e;
            c2049p2 = c2049p;
        }
    }

    /* renamed from: b */
    public final boolean m1457b() {
        return this.f3397c != null;
    }

    /* renamed from: c */
    public final void m1458c(boolean z, long j2) {
        this.f3397c = null;
        this.f3396b.mo1471b();
    }

    /* renamed from: d */
    public final int m1459d(C2003e c2003e, long j2, C2049p c2049p) {
        if (j2 == c2003e.f3789d) {
            return 0;
        }
        c2049p.f4187a = j2;
        return 1;
    }

    /* renamed from: e */
    public final void m1460e(long j2) {
        c cVar = this.f3397c;
        if (cVar == null || cVar.f3406a != j2) {
            long mo1465a = this.f3395a.f3399a.mo1465a(j2);
            a aVar = this.f3395a;
            this.f3397c = new c(j2, mo1465a, aVar.f3401c, aVar.f3402d, aVar.f3403e, aVar.f3404f, aVar.f3405g);
        }
    }

    /* renamed from: f */
    public final boolean m1461f(C2003e c2003e, long j2) {
        long j3 = j2 - c2003e.f3789d;
        if (j3 < 0 || j3 > 262144) {
            return false;
        }
        c2003e.m1569i((int) j3);
        return true;
    }
}
