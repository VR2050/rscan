package p005b.p199l.p200a.p201a.p208f1.p214f0;

import p005b.p199l.p200a.p201a.p208f1.AbstractC1965a;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.z */
/* loaded from: classes.dex */
public final class C2035z extends AbstractC1965a {

    /* renamed from: b.l.a.a.f1.f0.z$a */
    public static final class a implements AbstractC1965a.f {

        /* renamed from: a */
        public final C2342c0 f4123a;

        /* renamed from: b */
        public final C2360t f4124b = new C2360t();

        /* renamed from: c */
        public final int f4125c;

        public a(int i2, C2342c0 c2342c0) {
            this.f4125c = i2;
            this.f4123a = c2342c0;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.f
        /* renamed from: a */
        public AbstractC1965a.e mo1470a(C2003e c2003e, long j2) {
            long j3 = c2003e.f3789d;
            int min = (int) Math.min(112800L, c2003e.f3788c - j3);
            this.f4124b.m2593y(min);
            c2003e.m1565e(this.f4124b.f6133a, 0, min, false);
            C2360t c2360t = this.f4124b;
            int i2 = c2360t.f6135c;
            long j4 = -1;
            long j5 = -1;
            long j6 = -9223372036854775807L;
            while (c2360t.m2569a() >= 188) {
                byte[] bArr = c2360t.f6133a;
                int i3 = c2360t.f6134b;
                while (i3 < i2 && bArr[i3] != 71) {
                    i3++;
                }
                int i4 = i3 + 188;
                if (i4 > i2) {
                    break;
                }
                long m4764E0 = C4195m.m4764E0(c2360t, i3, this.f4125c);
                if (m4764E0 != -9223372036854775807L) {
                    long m2306b = this.f4123a.m2306b(m4764E0);
                    if (m2306b > j2) {
                        return j6 == -9223372036854775807L ? AbstractC1965a.e.m1467a(m2306b, j3) : AbstractC1965a.e.m1468b(j3 + j5);
                    }
                    if (100000 + m2306b > j2) {
                        return AbstractC1965a.e.m1468b(j3 + i3);
                    }
                    j6 = m2306b;
                    j5 = i3;
                }
                c2360t.m2567C(i4);
                j4 = i4;
            }
            return j6 != -9223372036854775807L ? AbstractC1965a.e.m1469c(j6, j3 + j4) : AbstractC1965a.e.f3414a;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.AbstractC1965a.f
        /* renamed from: b */
        public void mo1471b() {
            this.f4124b.m2594z(C2344d0.f6040f);
        }
    }

    public C2035z(C2342c0 c2342c0, long j2, long j3, int i2) {
        super(new AbstractC1965a.b(), new a(i2, c2342c0), j2, 0L, j2 + 1, 0L, j3, 188L, 940);
    }
}
