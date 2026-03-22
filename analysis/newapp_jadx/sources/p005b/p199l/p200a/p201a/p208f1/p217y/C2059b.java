package p005b.p199l.p200a.p201a.p208f1.p217y;

import p005b.p199l.p200a.p201a.p208f1.AbstractC1965a;
import p005b.p199l.p200a.p201a.p208f1.C1972b;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2044k;
import p005b.p199l.p200a.p201a.p250p1.C2353m;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.y.b */
/* loaded from: classes.dex */
public final class C2059b extends AbstractC1965a {

    /* renamed from: b.l.a.a.f1.y.b$b */
    public static final class b implements AbstractC1965a.f {

        /* renamed from: a */
        public final C2353m f4231a;

        /* renamed from: b */
        public final int f4232b;

        /* renamed from: c */
        public final C2044k.a f4233c = new C2044k.a();

        public b(C2353m c2353m, int i2, a aVar) {
            this.f4231a = c2353m;
            this.f4232b = i2;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.f
        /* renamed from: a */
        public AbstractC1965a.e mo1470a(C2003e c2003e, long j2) {
            long j3 = c2003e.f3789d;
            long m1642c = m1642c(c2003e);
            long m1564d = c2003e.m1564d();
            c2003e.m1561a(Math.max(6, this.f4231a.f6075c), false);
            long m1642c2 = m1642c(c2003e);
            return (m1642c > j2 || m1642c2 <= j2) ? m1642c2 <= j2 ? AbstractC1965a.e.m1469c(m1642c2, c2003e.m1564d()) : AbstractC1965a.e.m1467a(m1642c, j3) : AbstractC1965a.e.m1468b(m1564d);
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.f
        /* renamed from: b */
        public /* synthetic */ void mo1471b() {
            C1972b.m1500a(this);
        }

        /* renamed from: c */
        public final long m1642c(C2003e c2003e) {
            boolean m1627b;
            while (c2003e.m1564d() < c2003e.f3788c - 6) {
                C2353m c2353m = this.f4231a;
                int i2 = this.f4232b;
                C2044k.a aVar = this.f4233c;
                long m1564d = c2003e.m1564d();
                byte[] bArr = new byte[2];
                c2003e.m1565e(bArr, 0, 2, false);
                if ((((bArr[0] & 255) << 8) | (bArr[1] & 255)) != i2) {
                    c2003e.f3791f = 0;
                    c2003e.m1561a((int) (m1564d - c2003e.f3789d), false);
                    m1627b = false;
                } else {
                    C2360t c2360t = new C2360t(16);
                    System.arraycopy(bArr, 0, c2360t.f6133a, 0, 2);
                    c2360t.m2566B(C4195m.m4760C0(c2003e, c2360t.f6133a, 2, 14));
                    c2003e.f3791f = 0;
                    c2003e.m1561a((int) (m1564d - c2003e.f3789d), false);
                    m1627b = C2044k.m1627b(c2360t, c2353m, i2, aVar);
                }
                if (m1627b) {
                    break;
                }
                c2003e.m1561a(1, false);
            }
            long m1564d2 = c2003e.m1564d();
            long j2 = c2003e.f3788c;
            if (m1564d2 < j2 - 6) {
                return this.f4233c.f4166a;
            }
            c2003e.m1561a((int) (j2 - c2003e.m1564d()), false);
            return this.f4231a.f6082j;
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2059b(final p005b.p199l.p200a.p201a.p250p1.C2353m r17, int r18, long r19, long r21) {
        /*
            r16 = this;
            r0 = r17
            r17.getClass()
            b.l.a.a.f1.y.a r1 = new b.l.a.a.f1.y.a
            r1.<init>()
            b.l.a.a.f1.y.b$b r2 = new b.l.a.a.f1.y.b$b
            r3 = 0
            r4 = r18
            r2.<init>(r0, r4, r3)
            long r3 = r17.m2370d()
            long r7 = r0.f6082j
            int r5 = r0.f6076d
            if (r5 <= 0) goto L27
            long r5 = (long) r5
            int r9 = r0.f6075c
            long r9 = (long) r9
            long r5 = r5 + r9
            r9 = 2
            long r5 = r5 / r9
            r9 = 1
            goto L42
        L27:
            int r5 = r0.f6073a
            int r6 = r0.f6074b
            if (r5 != r6) goto L31
            if (r5 <= 0) goto L31
            long r5 = (long) r5
            goto L33
        L31:
            r5 = 4096(0x1000, double:2.0237E-320)
        L33:
            int r9 = r0.f6079g
            long r9 = (long) r9
            long r5 = r5 * r9
            int r9 = r0.f6080h
            long r9 = (long) r9
            long r5 = r5 * r9
            r9 = 8
            long r5 = r5 / r9
            r9 = 64
        L42:
            long r13 = r5 + r9
            r5 = 6
            int r0 = r0.f6075c
            int r15 = java.lang.Math.max(r5, r0)
            r5 = 0
            r0 = r16
            r9 = r19
            r11 = r21
            r0.<init>(r1, r2, r3, r5, r7, r9, r11, r13, r15)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p217y.C2059b.<init>(b.l.a.a.p1.m, int, long, long):void");
    }
}
