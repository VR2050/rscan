package p005b.p199l.p200a.p201a.p208f1.p214f0;

import p005b.p199l.p200a.p201a.p208f1.AbstractC1965a;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.s */
/* loaded from: classes.dex */
public final class C2028s extends AbstractC1965a {

    /* renamed from: b.l.a.a.f1.f0.s$b */
    public static final class b implements AbstractC1965a.f {

        /* renamed from: a */
        public final C2342c0 f4083a;

        /* renamed from: b */
        public final C2360t f4084b = new C2360t();

        public b(C2342c0 c2342c0, a aVar) {
            this.f4083a = c2342c0;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.f
        /* renamed from: a */
        public AbstractC1965a.e mo1470a(C2003e c2003e, long j2) {
            int m1607g;
            long j3 = c2003e.f3789d;
            int min = (int) Math.min(20000L, c2003e.f3788c - j3);
            this.f4084b.m2593y(min);
            c2003e.m1565e(this.f4084b.f6133a, 0, min, false);
            C2360t c2360t = this.f4084b;
            int i2 = -1;
            long j4 = -9223372036854775807L;
            int i3 = -1;
            while (c2360t.m2569a() >= 4) {
                if (C2028s.m1607g(c2360t.f6133a, c2360t.f6134b) != 442) {
                    c2360t.m2568D(1);
                } else {
                    c2360t.m2568D(4);
                    long m1608c = C2029t.m1608c(c2360t);
                    if (m1608c != -9223372036854775807L) {
                        long m2306b = this.f4083a.m2306b(m1608c);
                        if (m2306b > j2) {
                            return j4 == -9223372036854775807L ? AbstractC1965a.e.m1467a(m2306b, j3) : AbstractC1965a.e.m1468b(j3 + i3);
                        }
                        if (100000 + m2306b > j2) {
                            return AbstractC1965a.e.m1468b(j3 + c2360t.f6134b);
                        }
                        i3 = c2360t.f6134b;
                        j4 = m2306b;
                    }
                    int i4 = c2360t.f6135c;
                    if (c2360t.m2569a() >= 10) {
                        c2360t.m2568D(9);
                        int m2585q = c2360t.m2585q() & 7;
                        if (c2360t.m2569a() >= m2585q) {
                            c2360t.m2568D(m2585q);
                            if (c2360t.m2569a() >= 4) {
                                if (C2028s.m1607g(c2360t.f6133a, c2360t.f6134b) == 443) {
                                    c2360t.m2568D(4);
                                    int m2590v = c2360t.m2590v();
                                    if (c2360t.m2569a() < m2590v) {
                                        c2360t.m2567C(i4);
                                    } else {
                                        c2360t.m2568D(m2590v);
                                    }
                                }
                                while (true) {
                                    if (c2360t.m2569a() < 4 || (m1607g = C2028s.m1607g(c2360t.f6133a, c2360t.f6134b)) == 442 || m1607g == 441 || (m1607g >>> 8) != 1) {
                                        break;
                                    }
                                    c2360t.m2568D(4);
                                    if (c2360t.m2569a() < 2) {
                                        c2360t.m2567C(i4);
                                        break;
                                    }
                                    c2360t.m2567C(Math.min(c2360t.f6135c, c2360t.f6134b + c2360t.m2590v()));
                                }
                            } else {
                                c2360t.m2567C(i4);
                            }
                        } else {
                            c2360t.m2567C(i4);
                        }
                    } else {
                        c2360t.m2567C(i4);
                    }
                    i2 = c2360t.f6134b;
                }
            }
            return j4 != -9223372036854775807L ? AbstractC1965a.e.m1469c(j4, j3 + i2) : AbstractC1965a.e.f3414a;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.f
        /* renamed from: b */
        public void mo1471b() {
            this.f4084b.m2594z(C2344d0.f6040f);
        }
    }

    public C2028s(C2342c0 c2342c0, long j2, long j3) {
        super(new AbstractC1965a.b(), new b(c2342c0, null), j2, 0L, j2 + 1, 0L, j3, 188L, 1000);
    }

    /* renamed from: g */
    public static int m1607g(byte[] bArr, int i2) {
        return (bArr[i2 + 3] & 255) | ((bArr[i2] & 255) << 24) | ((bArr[i2 + 1] & 255) << 16) | ((bArr[i2 + 2] & 255) << 8);
    }
}
