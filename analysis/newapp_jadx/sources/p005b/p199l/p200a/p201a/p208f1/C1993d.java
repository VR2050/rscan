package p005b.p199l.p200a.p201a.p208f1;

import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.d */
/* loaded from: classes.dex */
public class C1993d implements InterfaceC2050q {

    /* renamed from: a */
    public final long f3720a;

    /* renamed from: b */
    public final long f3721b;

    /* renamed from: c */
    public final int f3722c;

    /* renamed from: d */
    public final long f3723d;

    /* renamed from: e */
    public final int f3724e;

    /* renamed from: f */
    public final long f3725f;

    public C1993d(long j2, long j3, int i2, int i3) {
        this.f3720a = j2;
        this.f3721b = j3;
        this.f3722c = i3 == -1 ? 1 : i3;
        this.f3724e = i2;
        if (j2 == -1) {
            this.f3723d = -1L;
            this.f3725f = -9223372036854775807L;
        } else {
            this.f3723d = j2 - j3;
            this.f3725f = m1544e(j2, j3, i2);
        }
    }

    /* renamed from: e */
    public static long m1544e(long j2, long j3, int i2) {
        return ((Math.max(0L, j2 - j3) * 8) * 1000000) / i2;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return this.f3723d != -1;
    }

    /* renamed from: d */
    public long m1545d(long j2) {
        return m1544e(j2, this.f3721b, this.f3724e);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        long j3 = this.f3723d;
        if (j3 == -1) {
            return new InterfaceC2050q.a(new C2051r(0L, this.f3721b));
        }
        long j4 = this.f3722c;
        long m2330h = this.f3721b + C2344d0.m2330h((((this.f3724e * j2) / 8000000) / j4) * j4, 0L, j3 - j4);
        long m1545d = m1545d(m2330h);
        C2051r c2051r = new C2051r(m1545d, m2330h);
        if (m1545d < j2) {
            int i2 = this.f3722c;
            if (i2 + m2330h < this.f3720a) {
                long j5 = m2330h + i2;
                return new InterfaceC2050q.a(c2051r, new C2051r(m1545d(j5), j5));
            }
        }
        return new InterfaceC2050q.a(c2051r);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f3725f;
    }
}
